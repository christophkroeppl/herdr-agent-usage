/**
 * Caches the last Kilo reading next to usage-history.json.
 *
 * Only the resolved ProviderLimits is stored — never the gateway login — so a
 * stale cache file cannot leak a credential. The entry is keyed by the login's
 * hashed identity, so an account switch refuses the previous account's numbers
 * instead of showing them against the new login.
 */
package limits

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	// A success is reused for two minutes. The sidebar collects on every pane
	// status change, so the window has to be long enough to matter and short
	// enough that a Kilo Pass purchase shows up promptly.
	kiloCacheSuccessTTLMs = 120_000
	// A failure is reused for longer: an account without a plan, or a revoked
	// login, must not re-hit the endpoint on every pane event.
	kiloCacheFailureTTLMs = 600_000
)

type kiloCacheOutcome string

const (
	kiloOutcomeFetched kiloCacheOutcome = "fetched"
	kiloOutcomeFailed  kiloCacheOutcome = "failed"
)

type kiloCacheEntry struct {
	FetchedAtMs int64            `json:"fetchedAtMs"`
	AccountID   string           `json:"accountId"`
	Outcome     kiloCacheOutcome `json:"outcome"`
	Limits      *ProviderLimits  `json:"limits,omitempty"`
}

func kiloCachePath() string {
	if v := os.Getenv("USAGEBAR_KILO_CACHE_PATH"); v != "" {
		return v
	}
	return filepath.Join(historyBaseDir(), "kilo-pass.json")
}

func kiloCacheTTL(outcome kiloCacheOutcome) int64 {
	if outcome == kiloOutcomeFetched {
		return kiloCacheSuccessTTLMs
	}
	return kiloCacheFailureTTLMs
}

// kiloCacheFresh requires the entry to name the same account that is signed in
// now. An entry with no account, or a different one, is not fresh no matter how
// recent it is.
func kiloCacheFresh(entry kiloCacheEntry, accountID string, nowMs int64) bool {
	if entry.FetchedAtMs <= 0 || nowMs < entry.FetchedAtMs {
		return false
	}
	if entry.Outcome == "" || entry.AccountID == "" || entry.AccountID != accountID {
		return false
	}
	return nowMs-entry.FetchedAtMs < kiloCacheTTL(entry.Outcome)
}

func loadKiloCache(nowMs int64, accountID string) (kiloCacheEntry, bool) {
	raw, err := os.ReadFile(kiloCachePath())
	if err != nil {
		return kiloCacheEntry{}, false
	}
	var entry kiloCacheEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return kiloCacheEntry{}, false
	}
	if !kiloCacheFresh(entry, accountID, nowMs) {
		return kiloCacheEntry{}, false
	}
	return entry, true
}

func saveKiloCache(entry kiloCacheEntry) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	path := kiloCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}
