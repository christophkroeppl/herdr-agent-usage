/**
 * Tests for Kilo context resolution against a real-shaped session store.
 *
 * The fixtures mirror the rows Kilo actually writes: step-finish parts carrying
 * per-step context, assistant messages naming the backend, and the denormalised
 * session totals Kilo backfills from its messages.
 */
package kilo

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// A step-finish row as Kilo writes it: prompt-cache occupancy for that step,
// with the model block only present on newer rows.
const stepWithModel = `{"reason":"tool-calls","type":"step-finish","time":{"start":1,"end":2,"elapsed":5592},
 "model":{"providerID":"kilo","modelID":"~openai/gpt-mini-latest"},
 "metrics":{"generation":79.04,"source":"computed"},
 "tokens":{"total":30494,"input":1219,"output":442,"reasoning":0,"cache":{"write":0,"read":28833}},
 "cost":0}`

// The same step on an older row, where the model is only on the message.
const stepWithoutModel = `{"reason":"tool-calls","type":"step-finish","time":{"start":1,"end":2,"elapsed":1},
 "tokens":{"total":74588,"input":74566,"output":4,"reasoning":18,"cache":{"write":0,"read":0}},
 "cost":0}`

const assistantMessage = `{"role":"assistant","mode":"general","cost":0,
 "tokens":{"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}},
 "modelID":"~openai/gpt-mini-latest","providerID":"kilo"}`

// A free-model step: every counter is zero. Reporting a 0-token context would
// present as an untouched window, so this must yield no usage at all.
const costOnlyStep = `{"type":"step-finish","tokens":{"total":0,"input":0,"output":0,"reasoning":0,
 "cache":{"read":0,"write":0}},"cost":0}`

// writeStore builds a Kilo session store with the given session rows.
func writeStore(t *testing.T, steps []string, messages []string, sessionCols [6]int, modelJSON string) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kilo.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE session (
		id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER DEFAULT 0,
		time_archived INTEGER, cost REAL DEFAULT 0 NOT NULL,
		tokens_input INTEGER DEFAULT 0 NOT NULL, tokens_output INTEGER DEFAULT 0 NOT NULL,
		tokens_reasoning INTEGER DEFAULT 0 NOT NULL, tokens_cache_read INTEGER DEFAULT 0 NOT NULL,
		tokens_cache_write INTEGER DEFAULT 0 NOT NULL, model TEXT)`)
	mustExec(t, db, `CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT,
		time_created INTEGER, data TEXT)`)
	mustExec(t, db, `CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
		time_created INTEGER, data TEXT)`)
	mustExec(t, db, `CREATE INDEX part_session_step_finish_idx ON part (session_id)
		WHERE json_valid(part.data) AND json_extract(part.data,'$.type') = 'step-finish'`)

	cost := 0.5
	_, err = db.Exec(`INSERT INTO session (id, directory, cost, tokens_input, tokens_output,
		tokens_reasoning, tokens_cache_read, tokens_cache_write, model)
		VALUES ('ses_test', ?, ?, ?, ?, ?, ?, ?, ?)`,
		"/repo", cost, sessionCols[0], sessionCols[1], sessionCols[2], sessionCols[3], sessionCols[4], modelJSON)
	if err != nil {
		t.Fatal(err)
	}
	for i, data := range messages {
		_, err := db.Exec(`INSERT INTO message (id, session_id, time_created, data) VALUES (?,?,?,?)`,
			"msg_"+string(rune('a'+i)), "ses_test", 100-i, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, data := range steps {
		_, err := db.Exec(`INSERT INTO part (id, message_id, session_id, time_created, data) VALUES (?,?,?,?,?)`,
			"prt_"+string(rune('a'+i)), "msg_a", "ses_test", 100-i, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func mustExec(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func useStore(t *testing.T, dbPath string) {
	t.Helper()
	t.Setenv("KILO_DB", dbPath)
	t.Setenv("KILO_DATA_DIR", "")
}

func strPtr(s string) *string { return &s }

func TestResolveUsage_NewestStepCarriesContextAndWindow(t *testing.T) {
	dir := t.TempDir()
	models := filepath.Join(dir, "models.json")
	if err := os.WriteFile(models, []byte(
		`{"kilo":{"models":{"~openai/gpt-mini-latest":{"limit":{"context":1000000}}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KILO_MODELS_PATH", models)
	ClearModelsCatalogCache()

	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	usage := ResolveUsageForKilo(strPtr("ses_test"), strPtr("/repo"))
	if usage == nil {
		t.Fatal("no usage")
	}
	// Context is prompt-cache occupancy: input + cache read + cache write. The
	// 442 output tokens are already inside the next step's input, so counting
	// them here would double-count the window.
	if usage.ContextTokens != 1219+28833 {
		t.Fatalf("context tokens = %d", usage.ContextTokens)
	}
	if usage.WindowTokens == nil || *usage.WindowTokens != 1000000 {
		t.Fatalf("window = %v", usage.WindowTokens)
	}
	if usage.Cache == nil || usage.Cache.ReadTokens != 28833 || usage.Cache.FreshInputTokens != 1219 {
		t.Fatalf("cache = %+v", usage.Cache)
	}
}

func TestResolveUsage_ModelComesFromTheMessageWhenTheStepHasNone(t *testing.T) {
	// Only 88 of Kilo's 9140 step rows carry their own model block, so the
	// message is the normal source of the backend name.
	t.Setenv("KILO_MODELS_PATH", filepath.Join(t.TempDir(), "absent.json"))
	ClearModelsCatalogCache()

	dbPath := writeStore(t, []string{stepWithoutModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	usage := ResolveUsageForKilo(strPtr("ses_test"), strPtr("/repo"))
	if usage == nil {
		t.Fatal("no usage")
	}
	if usage.WindowTokens != nil {
		t.Fatalf("unknown model must yield no window, got %v", *usage.WindowTokens)
	}
	if backend := BackendForKilo(strPtr("ses_test")); backend != "kilo" {
		t.Fatalf("backend = %q", backend)
	}
}

func TestResolveUsage_CostOnlyStepYieldsNoUsage(t *testing.T) {
	// Kilo records free-model steps with every counter at zero. Reading that as
	// a 0-token context would present as an untouched window.
	dbPath := writeStore(t, []string{costOnlyStep}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	if usage := ResolveUsageForKilo(strPtr("ses_test"), strPtr("/repo")); usage != nil {
		t.Fatalf("cost-only step produced usage: %+v", usage)
	}
}

func TestResolveUsage_UnknownSessionFallsBackToCwd(t *testing.T) {
	// Herdr captures the session id at launch and never refreshes it, so a
	// cleared or resumed session reports an id that no longer exists.
	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	if usage := ResolveUsageForKilo(strPtr("ses_stale"), strPtr("/repo")); usage == nil {
		t.Fatal("cwd fallback did not recover the session")
	}
	if usage := ResolveUsageForKilo(strPtr("ses_stale"), strPtr("/elsewhere")); usage != nil {
		t.Fatalf("wrong cwd resolved usage: %+v", usage)
	}
}

func TestResolveUsage_NoIdentifiersYieldsNothing(t *testing.T) {
	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	if usage := ResolveUsageForKilo(nil, nil); usage != nil {
		t.Fatalf("no identifiers produced usage: %+v", usage)
	}
	if usage := ResolveUsageForKilo(strPtr(""), strPtr("")); usage != nil {
		t.Fatalf("blank identifiers produced usage: %+v", usage)
	}
}

func TestResolveUsage_TwoPanesInOneRepoDoNotCrossAttribute(t *testing.T) {
	// Two Kilo panes in one repository share a cwd, so a session that cannot be
	// resolved by id must not borrow the other pane's session by directory.
	// Pinning the id is what keeps them apart.
	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	if usage := ResolveUsageForKilo(strPtr("ses_test"), nil); usage == nil {
		t.Fatal("id-only resolution failed")
	}
	if usage := ResolveUsageForKilo(nil, strPtr("/repo")); usage == nil {
		t.Fatal("cwd-only resolution failed for a single session")
	}
	// A second session in the same directory must be the only candidate, so a
	// pane pinned to a real id never resolves the other one.
	if usage := ResolveUsageForKilo(strPtr("ses_absent"), strPtr("/repo")); usage == nil {
		t.Fatal("recovery path failed")
	}
}

func TestResolveUsage_AbsentStoreYieldsNothing(t *testing.T) {
	t.Setenv("KILO_DB", filepath.Join(t.TempDir(), "absent.db"))
	if usage := ResolveUsageForKilo(strPtr("ses_test"), strPtr("/repo")); usage != nil {
		t.Fatalf("absent store produced usage: %+v", usage)
	}
	t.Setenv("KILO_DB", "")
	t.Setenv("KILO_DATA_DIR", t.TempDir())
	if usage := ResolveUsageForKilo(strPtr("ses_test"), strPtr("/repo")); usage != nil {
		t.Fatalf("empty data dir produced usage: %+v", usage)
	}
}

func TestSessionSummary_ReadsDenormalisedTotals(t *testing.T) {
	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage},
		[6]int{10, 20, 30, 40, 50},
		`{"id":"mimo-v2.6-pro","providerID":"opencode-go","variant":"default"}`)
	useStore(t, dbPath)

	summary, ok := SessionSummaryForKilo(strPtr("ses_test"))
	if !ok {
		t.Fatal("summary not read")
	}
	if summary.Cost != 0.5 {
		t.Fatalf("cost = %v", summary.Cost)
	}
	if summary.TotalTokens() != 150 {
		t.Fatalf("total tokens = %d", summary.TotalTokens())
	}
	if summary.ProviderID != "opencode-go" || summary.ModelID != "mimo-v2.6-pro" {
		t.Fatalf("identity = %+v", summary)
	}
	if _, ok := SessionSummaryForKilo(strPtr("ses_absent")); ok {
		t.Fatal("absent session produced a summary")
	}
	if _, ok := SessionSummaryForKilo(nil); ok {
		t.Fatal("nil session id produced a summary")
	}
}

func TestSessionSummary_EmptyModelColumnIsNormal(t *testing.T) {
	// session.model is populated on only some sessions; an empty value must
	// leave the identity blank rather than fail the read.
	dbPath := writeStore(t, []string{stepWithModel}, []string{assistantMessage}, [6]int{}, "")
	useStore(t, dbPath)

	summary, ok := SessionSummaryForKilo(strPtr("ses_test"))
	if !ok {
		t.Fatal("summary not read")
	}
	if summary.ProviderID != "" || summary.ModelID != "" {
		t.Fatalf("identity invented: %+v", summary)
	}
}

func TestQueriesAreBoundedAndReadOnly(t *testing.T) {
	// A whole-table scan would be a bug: the store is a live WAL database with
	// hundreds of thousands of rows.
	for _, query := range []string{stepQuery, identityQuery, summaryQuery} {
		if !contains(query, "session_id = ?") && !contains(query, "WHERE id = ?") {
			t.Fatalf("query is not scoped to one session: %s", query)
		}
	}
	if !contains(stepQuery, "LIMIT ?") || !contains(identityQuery, "LIMIT 1") {
		t.Fatalf("queries are unbounded: %s / %s", stepQuery, identityQuery)
	}
	if contains(stepQuery, "SUM(") {
		t.Fatalf("step query aggregates instead of reading the newest row")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
