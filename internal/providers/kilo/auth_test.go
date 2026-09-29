/**
 * Tests for Kilo's credential reader.
 *
 * The property under test is attribution: only the gateway device login may
 * stand behind a reading, and a gateway API key never may, because it bills the
 * same account while naming none.
 */
package kilo

import "testing"

const storeWithBothKinds = `{
	"kilo": {"type":"oauth","refresh":"rt_secret","access":"st_access","expires":999},
	"opencode-go": {"type":"api","key":"og_secret"},
	"openrouter": {"type":"api"}
}`

func TestCredentialType_ReportsTheKindOnly(t *testing.T) {
	auth := ParseAuthJSON([]byte(storeWithBothKinds))
	if got := CredentialTypeIn(auth, "kilo"); got != "oauth" {
		t.Fatalf("kilo kind = %q", got)
	}
	if got := CredentialTypeIn(auth, "opencode-go"); got != "api" {
		t.Fatalf("opencode-go kind = %q", got)
	}
	if got := CredentialTypeIn(auth, "absent"); got != "" {
		t.Fatalf("absent provider = %q, want empty", got)
	}
}

func TestCredentialType_DoesNotLeakSecrets(t *testing.T) {
	// The kind is the whole contract: a caller that could read the value would
	// start using it for attribution, which is exactly what must not happen.
	auth := ParseAuthJSON([]byte(storeWithBothKinds))
	if got := CredentialTypeIn(auth, "kilo"); len(got) > 0 && (got == "st_access" || got == "rt_secret") {
		t.Fatalf("credential kind returned secret material: %q", got)
	}
}

func TestGatewayLogin_AcceptsOnlyTheDeviceLogin(t *testing.T) {
	// A gateway API key bills the same account but cannot name it, so it is
	// never the attribution for a reading.
	for name, store := range map[string]string{
		"api key":        `{"kilo":{"type":"api","key":"sk-gateway"}}`,
		"blank access":   `{"kilo":{"type":"oauth","refresh":"rt","access":"   "}}`,
		"no access":      `{"kilo":{"type":"oauth","refresh":"rt"}}`,
		"wrong type":     `{"kilo":{"type":"wellknown","key":"sk"}}`,
		"other provider": `{"opencode-go":{"type":"oauth","access":"og"}}`,
		"not json":       `{not json`,
	} {
		auth := ParseAuthJSON([]byte(store))
		if got := GatewayLoginIn(auth); got != nil {
			t.Fatalf("%s: accepted a credential it must refuse: %+v", name, got.AccountID)
		}
	}
}

func TestGatewayLogin_ReadsTheDeviceLoginAndStampsAnIdentity(t *testing.T) {
	auth := ParseAuthJSON([]byte(storeWithBothKinds))
	got := GatewayLoginIn(auth)
	if got == nil {
		t.Fatal("gateway device login was refused")
	}
	if got.Access != "st_access" {
		t.Fatalf("access = %q", got.Access)
	}
	// The identity is a hash, so it can key a cache without the token ever
	// reaching disk.
	if got.AccountID == "" || got.AccountID == got.Access {
		t.Fatalf("account identity is not an opaque hash: %q", got.AccountID)
	}
}

func TestGatewayLogin_DifferentLoginsGetDifferentIdentities(t *testing.T) {
	// This is what makes a cached reading refusable: another login must produce
	// a different identity, or one account's numbers could answer for another.
	first := GatewayLoginIn(ParseAuthJSON([]byte(`{"kilo":{"type":"oauth","access":"tok_a"}}`)))
	second := GatewayLoginIn(ParseAuthJSON([]byte(`{"kilo":{"type":"oauth","access":"tok_b"}}`)))
	if first == nil || second == nil {
		t.Fatal("expected both logins to resolve")
	}
	if first.AccountID == second.AccountID {
		t.Fatalf("two logins share one identity: %q", first.AccountID)
	}
	if first.AccountID != AccountIDForToken("tok_a") {
		t.Fatalf("identity is not stable for one login: %q", first.AccountID)
	}
}

func TestIsGatewayProvider(t *testing.T) {
	for _, id := range []string{"kilo", "KILO", " kilo "} {
		if !IsGatewayProvider(id) {
			t.Fatalf("%q should be the gateway", id)
		}
	}
	for _, id := range []string{"opencode-go", "openrouter", "", "kilocode"} {
		if IsGatewayProvider(id) {
			t.Fatalf("%q should not be the gateway", id)
		}
	}
}

func TestParseAuthJSON_SkipsUnparsableEntries(t *testing.T) {
	// One bad entry must not discard the good ones beside it.
	auth := ParseAuthJSON([]byte(`{"kilo":"not-an-object","opencode-go":{"type":"api","key":"x"}}`))
	if got := CredentialTypeIn(auth, "kilo"); got != "" {
		t.Fatalf("unparsable entry produced a kind: %q", got)
	}
	if got := CredentialTypeIn(auth, "opencode-go"); got != "api" {
		t.Fatalf("sibling entry lost: %q", got)
	}
}
