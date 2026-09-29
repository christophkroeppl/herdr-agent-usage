/**
 * Resolves context usage for one Kilo pane from Kilo's session store.
 *
 * Context comes from the newest completed "step-finish" part of that session,
 * which is the row Kilo itself uses for its "Token Usage" panel. Reading the
 * step rather than summing a message's counters matters: a step carries the
 * exact prompt-cache occupancy for that request, while a message's counters
 * mix in output and reasoning tokens that the next step has already absorbed.
 *
 * Every read is bounded and read-only. Kilo's database is a live WAL database
 * with a partial index over exactly this query, so it is opened with mode=ro
 * and never scanned whole.
 */
package kilo

import (
	"database/sql"
	"strings"

	"github.com/senna-lang/herdr-agent-usage/internal/core"
	_ "modernc.org/sqlite"
)

// stepScanLimit bounds the step-finish tail read for one session. The newest
// row is all that is needed; the rest exist so that a session whose newest step
// was compacted or truncated still resolves from an earlier one.
const stepScanLimit = 24

const stepQuery = `
	SELECT p.data
	FROM part p
	WHERE p.session_id = ?
	  AND json_extract(p.data, '$.type') = 'step-finish'
	ORDER BY p.time_created DESC
	LIMIT ?`

const identityQuery = `
	SELECT m.data
	FROM message m
	WHERE m.session_id = ?
	  AND json_extract(m.data, '$.role') = 'assistant'
	  AND json_extract(m.data, '$.providerID') IS NOT NULL
	ORDER BY m.time_created DESC
	LIMIT 1`

const summaryQuery = `
	SELECT cost, tokens_input, tokens_output, tokens_reasoning,
	       tokens_cache_read, tokens_cache_write, model
	FROM session
	WHERE id = ?
	LIMIT 1`

func openReadonlyDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?mode=ro")
}

// ResolveUsageForKilo resolves context usage from a session id, falling back to
// the pane's cwd only when the reported id no longer resolves.
//
// The cwd fallback is the last step, not the first: two Kilo panes in one
// repository share a cwd, so matching a session by directory alone would let
// them cross-attribute. It runs only when the id herdr reported is gone, which
// is the one case where nothing better exists.
func ResolveUsageForKilo(sessionID, cwd *string) *core.ContextUsage {
	dbPath := ResolveKiloDBPath()
	if dbPath == "" {
		return nil
	}
	return resolveUsageIn(dbPath, sessionID, cwd)
}

// ResolveUsageForKiloIn resolves usage from one configured data directory and
// never consults KILO_DB or KILO_DATA_DIR.
func ResolveUsageForKiloIn(dataDir string, sessionID, cwd *string) *core.ContextUsage {
	dbPath := ResolveKiloDBPathIn(dataDir)
	if dbPath == "" {
		return nil
	}
	return resolveUsageIn(dbPath, sessionID, cwd)
}

func resolveUsageIn(dbPath string, sessionID, cwd *string) *core.ContextUsage {
	db, err := openReadonlyDB(dbPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	id := ""
	if sessionID != nil {
		id = strings.TrimSpace(*sessionID)
	}
	// An empty cwd is no identifier at all, and must not reach the fallback:
	// the directory match is a LIKE, so an empty prefix would match every
	// session in the store.
	directory := ""
	if cwd != nil {
		directory = strings.TrimSpace(*cwd)
	}
	if id == "" {
		if directory == "" {
			return nil
		}
		id = resolveSessionIDByCwd(db, directory)
	}
	if id == "" {
		return nil
	}

	var found int
	if err := db.QueryRow(`SELECT 1 AS ok FROM session WHERE id = ? LIMIT 1`, id).Scan(&found); err != nil {
		// Herdr captures the session id at launch and never refreshes it, so a
		// cleared or resumed session reports an id that no longer exists.
		// Recovering by cwd is honest here because there is nothing to cross
		// against; the first attempt was pane-scoped and has already failed.
		if directory == "" {
			return nil
		}
		id = resolveSessionIDByCwd(db, directory)
		if id == "" {
			return nil
		}
	}

	step := latestStepUsage(db, id)
	if step == nil {
		return nil
	}
	if step.ProviderID == "" {
		// Only 88 of Kilo's 9140 step rows carry their own model block, so the
		// identity almost always comes from the assistant message.
		if identity := latestMessageIdentity(db, id); identity.ProviderID != "" {
			step.ProviderID = identity.ProviderID
			if step.ModelID == "" {
				step.ModelID = identity.ModelID
			}
		}
	}

	usage := core.ContextUsage{
		ContextTokens: step.ContextTokens,
		Cache:         core.CacheFromTokenCounts(step.CacheFresh, step.CacheRead, step.CacheWrite),
		SessionCache:  sessionCache(db, id, step),
	}
	if window := ContextWindowFor(step.ProviderID, step.ModelID); window != nil {
		usage.WindowTokens = window
	}
	return &usage
}

func resolveSessionIDByCwd(db *sql.DB, cwd string) string {
	var id string
	// Exact directory first, then a child worktree of it. Archived sessions are
	// excluded: an archived session's context is not what a live pane is using.
	if err := db.QueryRow(
		`SELECT id FROM session
		 WHERE directory = ? AND time_archived IS NULL
		 ORDER BY time_updated DESC LIMIT 1`, cwd).Scan(&id); err == nil && id != "" {
		return id
	}
	if err := db.QueryRow(
		`SELECT id FROM session
		 WHERE directory LIKE ? AND time_archived IS NULL
		 ORDER BY time_updated DESC LIMIT 1`, escapeLike(cwd)+"%").Scan(&id); err == nil {
		return id
	}
	return ""
}

// escapeLike neutralises the wildcards in a directory path before it is used in
// a LIKE comparison, so a repo checked out under a directory containing "_"
// cannot match an unrelated session.
func escapeLike(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")
	return replacer.Replace(value)
}

func latestStepUsage(db *sql.DB, sessionID string) *StepUsage {
	rows, err := db.Query(stepQuery, sessionID, stepScanLimit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		if usage := ParseStepUsage(raw); usage != nil {
			return usage
		}
	}
	return nil
}

func latestMessageIdentity(db *sql.DB, sessionID string) MessageIdentity {
	rows, err := db.Query(identityQuery, sessionID)
	if err != nil {
		return MessageIdentity{}
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		return ParseMessageIdentity(raw)
	}
	return MessageIdentity{}
}

// sessionCache sums the prompt-cache counters across the scanned step tail.
// Only the steps actually read are counted, so the figure is a bounded sample
// of the transcript rather than a claim about the whole session; the latest
// turn's own figures stay in Cache.
func sessionCache(db *sql.DB, sessionID string, newest *StepUsage) *core.CacheUsage {
	rows, err := db.Query(stepQuery, sessionID, stepScanLimit)
	if err != nil {
		return core.CacheFromTokenCounts(newest.CacheFresh, newest.CacheRead, newest.CacheWrite)
	}
	defer rows.Close()
	fresh, read, write := 0, 0, 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		if usage := ParseStepUsage(raw); usage != nil {
			fresh += usage.CacheFresh
			read += usage.CacheRead
			write += usage.CacheWrite
		}
	}
	return core.CacheFromTokenCounts(fresh, read, write)
}

// SessionSummaryForKilo reads the session's own denormalised totals.
//
// Kilo backfills these columns from its assistant messages, so they are the
// cheapest steady source of per-session cost and token movement. They are
// lifetime session totals, not a window: use them for pane activity and cost
// labels, never for a context percentage.
func SessionSummaryForKilo(sessionID *string) (SessionSummary, bool) {
	if sessionID == nil || *sessionID == "" {
		return SessionSummary{}, false
	}
	dbPath := ResolveKiloDBPath()
	if dbPath == "" {
		return SessionSummary{}, false
	}
	return sessionSummaryIn(dbPath, *sessionID)
}

func sessionSummaryIn(dbPath, sessionID string) (SessionSummary, bool) {
	db, err := openReadonlyDB(dbPath)
	if err != nil {
		return SessionSummary{}, false
	}
	defer db.Close()

	var (
		cost                                  float64
		input, output, reasoning, read, write int
		modelJSON                             string
	)
	row := db.QueryRow(summaryQuery, sessionID)
	if err := row.Scan(&cost, &input, &output, &reasoning, &read, &write, &modelJSON); err != nil {
		return SessionSummary{}, false
	}
	return SessionSummaryFromRow(cost, input, output, reasoning, read, write, modelJSON), true
}

// BackendForKilo reports which backend a session's model was served by.
//
// Kilo drives several providers, so the backend is what decides whether a pane
// owns a Kilo allowance at all. It comes from the assistant message rather
// than session.model, which Kilo only populates on newer sessions.
func BackendForKilo(sessionID *string) string {
	if sessionID == nil || *sessionID == "" {
		return ""
	}
	dbPath := ResolveKiloDBPath()
	if dbPath == "" {
		return ""
	}
	db, err := openReadonlyDB(dbPath)
	if err != nil {
		return ""
	}
	defer db.Close()
	return latestMessageIdentity(db, *sessionID).ProviderID
}
