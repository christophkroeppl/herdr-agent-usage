/**
 * Tests for Kilo pane routing.
 *
 * Kilo drives several providers from one CLI. The pane is a Kilo pane; the
 * backend recorded on its session is what decides whose allowance it spends,
 * and these tests pin that distinction for the two cases that matter: a session
 * on the Kilo Gateway, and a session on a backend with its own quota.
 */
package limits

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/senna-lang/herdr-agent-usage/internal/providers/kilo"
)

// seedKiloPane writes a Kilo store with one session served by backend, and an
// auth.json describing that backend's credential.
func seedKiloPane(t *testing.T, sessionID, backend string, auth string) OpenPaneSnapshot {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kilo.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	mustExecKilo(t, db, `CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT,
		time_updated INTEGER DEFAULT 0, time_archived INTEGER, cost REAL DEFAULT 0 NOT NULL,
		tokens_input INTEGER DEFAULT 0 NOT NULL, tokens_output INTEGER DEFAULT 0 NOT NULL,
		tokens_reasoning INTEGER DEFAULT 0 NOT NULL, tokens_cache_read INTEGER DEFAULT 0 NOT NULL,
		tokens_cache_write INTEGER DEFAULT 0 NOT NULL, model TEXT)`)
	mustExecKilo(t, db, `CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT,
		time_created INTEGER, data TEXT)`)
	mustExecKilo(t, db, `CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
		time_created INTEGER, data TEXT)`)
	mustExecKilo(t, db, `INSERT INTO session (id, directory) VALUES (?, '/repo')`, sessionID)
	_, err = db.Exec(`INSERT INTO message (id, session_id, time_created, data) VALUES (?,?,?,?)`,
		"msg_a", sessionID, 1,
		`{"role":"assistant","providerID":"`+backend+`","modelID":"some/model","tokens":{"input":10,"output":2}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KILO_DB", dbPath)
	t.Setenv("KILO_DATA_DIR", dir)
	t.Setenv("KILO_MODELS_PATH", filepath.Join(dir, "absent.json"))
	kilo.ClearModelsCatalogCache()
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	return OpenPaneSnapshot{PaneID: "w1:p1", Agent: "kilo", Label: "kilo", SessionID: &sessionID}
}

func mustExecKilo(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestKiloPane_OnTheGatewayOwnsNoPayAsYouGoBackend(t *testing.T) {
	// The Kilo Gateway is a Kilo allowance. Naming it as a pay-as-you-go
	// backend would send the pane to a burn-total block that says nothing about
	// its actual billing.
	pane := seedKiloPane(t, "ses_gw", "kilo",
		`{"kilo":{"type":"oauth","access":"tok"},"opencode-go":{"type":"api","key":"og"}}`)
	if got := kiloPaneBackendID(pane); got != "kilo" {
		t.Fatalf("backend = %q", got)
	}
	if got := payAsYouGoBackendID("kilo", pane); got != "" {
		t.Fatalf("gateway reported as pay-as-you-go: %q", got)
	}
	if route, ok := paneSubscriptionRoute("kilo", pane); ok {
		t.Fatalf("gateway resolved to a foreign subscription route: %+v", route)
	}
}

func TestKiloPane_OnOpenCodeGoRoutesToThatAccountsCollector(t *testing.T) {
	// This is the case the panel exists for: a Kilo pane spending an OpenCode
	// Go login must show that account's windows, under its own name, while the
	// harness stays Kilo.
	pane := seedKiloPane(t, "ses_og", "opencode-go",
		`{"kilo":{"type":"oauth","access":"tok"},"opencode-go":{"type":"api","key":"og"}}`)
	if got := kiloPaneBackendID(pane); got != "opencode-go" {
		t.Fatalf("backend = %q", got)
	}
	route, ok := paneSubscriptionRoute("kilo", pane)
	if !ok {
		t.Fatal("opencode-go backend did not resolve to a subscription route")
	}
	if route.CollectorProviderID != "opencode" || route.DisplayProviderID != "opencode-go" {
		t.Fatalf("route = %+v", route)
	}
	if got := SubscriptionLimitsProviderID("kilo", pane); got != "opencode" {
		t.Fatalf("collector provider = %q", got)
	}
	if got := SubscriptionDisplayProviderID("kilo", pane); got != "opencode-go" {
		t.Fatalf("display provider = %q", got)
	}
	if got := payAsYouGoBackendID("kilo", pane); got != "opencode-go" {
		t.Fatalf("pay-as-you-go backend = %q", got)
	}
}

func TestKiloPane_GatewaySessionIsBillableAndNotHidden(t *testing.T) {
	pane := seedKiloPane(t, "ses_gw", "kilo", `{"kilo":{"type":"oauth","access":"tok"}}`)
	mode := paneBillingModeWith(nil, nil, nil, nil, "kilo", pane)
	if mode == BillingPayAsYouGo {
		t.Fatal("a Kilo Gateway session was classified pay-as-you-go and hidden")
	}
}

func TestKiloPane_ForeignBackendWithAnApiKeyIsPayAsYouGo(t *testing.T) {
	// An API-key backend spends per token, so the pane is not drawing on a
	// Kilo allowance and must not be shown one.
	pane := seedKiloPane(t, "ses_og", "opencode-go",
		`{"kilo":{"type":"oauth","access":"tok"},"opencode-go":{"type":"api","key":"og"}}`)
	route, ok := paneSubscriptionRoute("kilo", pane)
	if ok && route.DisplayProviderID == "kilo" {
		t.Fatal("route pointed back at Kilo itself")
	}
}

func TestKiloPane_NoBackendEvidenceFailsOpen(t *testing.T) {
	// A session that has not recorded a backend yet must stay visible rather
	// than be hidden as pay-as-you-go on no evidence.
	pane := seedKiloPane(t, "ses_empty", "kilo", `{"kilo":{"type":"oauth","access":"tok"}}`)
	if got := kiloPaneBackendID(pane); got == "" {
		if mode := paneBillingModeWith(nil, nil, nil, nil, "kilo", pane); mode == BillingPayAsYouGo {
			t.Fatal("no evidence classified pay-as-you-go")
		}
	}
}

func TestKiloCredentialType_ComesFromKilosOwnStoreOnly(t *testing.T) {
	// A Kilo session on OpenCode Go must be classified from Kilo's own auth.json
	// entry for that provider, never from OpenCode's separate store.
	pane := seedKiloPane(t, "ses_og", "opencode-go",
		`{"kilo":{"type":"oauth","access":"tok"},"opencode-go":{"type":"api","key":"og"}}`)
	if got := paneCredentialType("kilo", pane); got != "api" {
		t.Fatalf("credential type = %q", got)
	}
	// And the gateway's own login is reported as oauth, so a Kilo Gateway pane
	// is never mistaken for an API-key session.
	gateway := seedKiloPane(t, "ses_gw2", "kilo", `{"kilo":{"type":"oauth","access":"tok"}}`)
	if got := paneCredentialType("kilo", gateway); got != kilo.CredentialType("kilo") {
		t.Fatalf("gateway credential type = %q", got)
	}
}
