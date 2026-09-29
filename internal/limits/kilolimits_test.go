/**
 * Tests for Kilo limit collection.
 *
 * The property under test throughout: Kilo publishes a monthly credit allowance
 * and nothing shorter, and publishes no allowance at all without a Kilo Pass
 * subscription. So a window may only ever come from a subscription, and every
 * other case must produce a note naming the cause rather than a fabricated bar.
 *
 * No test here reaches the network: both fetchers are injected.
 */
package limits

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/senna-lang/herdr-agent-usage/internal/providers/kilo"
)

const nowMs int64 = 1_787_000_000_000

// kiloStore writes a Kilo auth.json holding one gateway device login.
func kiloStore(t *testing.T, access string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	raw := `{"kilo":{"type":"oauth","refresh":"rt","access":"` + access + `"},"opencode-go":{"type":"api","key":"og"}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// collect runs the collector against pinned fetchers and an isolated cache.
func collect(t *testing.T, authPath string, pass *KiloPassState, passErr error, balance *KiloBalance, balanceErr error) ProviderLimits {
	t.Helper()
	t.Setenv("USAGEBAR_KILO_CACHE_PATH", filepath.Join(t.TempDir(), "kilo-cache.json"))
	return CollectKiloLimits(nowMs, CollectKiloLimitsOptions{
		AuthPath: authPath,
		FetchPass: func(string) (*KiloPassState, error) {
			return pass, passErr
		},
		FetchBalance: func(string) (*KiloBalance, error) {
			return balance, balanceErr
		},
	})
}

// A Kilo Pass subscriber with a 20.00 base allowance plus 10.00 of bonus
// credits, 3.42 spent, renewing at a known instant.
func subscribed() *KiloPassState {
	return &KiloPassState{
		BaseCreditsUSD:    20,
		BonusCreditsUSD:   10,
		UsageUSD:          3.42,
		NextBillingAt:     "2026-10-11T10:09:35Z",
		Status:            "active",
		HasAllowanceParts: true,
		HasUsageParts:     true,
	}
}

func TestCollectKiloLimits_ASubscriberGetsExactlyOneMonthlyWindow(t *testing.T) {
	pl := collect(t, kiloStore(t, "tok"), subscribed(), nil, &KiloBalance{Balance: 12.5}, nil)

	if pl.ProviderID != "kilo" || pl.Label != "Kilo" {
		t.Fatalf("identity = %+v", pl)
	}
	// Kilo publishes no 5h or 7h bucket. Those windows must stay nil rather
	// than borrow the monthly number, so the sidebar shows no short-window bar.
	if pl.Primary != nil || pl.Secondary != nil {
		t.Fatalf("short windows invented: %+v", pl)
	}
	if pl.Tertiary == nil {
		t.Fatal("no monthly window")
	}
	// 3.42 of a 30.00 allowance: the bonus credits are granted into the same
	// period and expire with it, so they are allowance too.
	if pl.Tertiary.UsedPercentage < 11.39 || pl.Tertiary.UsedPercentage > 11.41 {
		t.Fatalf("used = %v", pl.Tertiary.UsedPercentage)
	}
	if pl.Tertiary.WindowMinutes == nil || *pl.Tertiary.WindowMinutes != 43200 {
		t.Fatalf("window minutes = %v", pl.Tertiary.WindowMinutes)
	}
	if pl.Tertiary.ResetsAt == nil {
		t.Fatal("no reset time")
	}
	if pl.PlanType == nil || !strings.Contains(*pl.PlanType, "Kilo Pass") {
		t.Fatalf("plan = %v", pl.PlanType)
	}
	if pl.Note == nil || !strings.Contains(*pl.Note, "balance $12.50") {
		t.Fatalf("note = %v", pl.Note)
	}
}

func TestCollectKiloLimits_NoSubscriptionShowsBalanceAndNoBar(t *testing.T) {
	// The state most accounts are in: no Kilo Pass, paying from a shared credit
	// balance. There is no limit to draw a percentage against, so there is no
	// bar — only the facts that were actually reported.
	pl := collect(t, kiloStore(t, "tok"), &KiloPassState{}, nil, &KiloBalance{Balance: 0, IsDepleted: true}, nil)

	for _, w := range []*LimitWindow{pl.Primary, pl.Secondary, pl.Tertiary} {
		if w != nil {
			t.Fatalf("window invented without a subscription: %+v", w)
		}
	}
	if pl.Note == nil {
		t.Fatal("no note")
	}
	for _, want := range []string{"balance $0.00", "depleted", "no Kilo Pass"} {
		if !strings.Contains(*pl.Note, want) {
			t.Fatalf("note %q lacks %q", *pl.Note, want)
		}
	}
	// The note must say why there is no percentage, not merely omit one.
	if !strings.Contains(*pl.Note, "without a limit") {
		t.Fatalf("note does not explain the absent quota: %q", *pl.Note)
	}
}

func TestCollectKiloLimits_NoGatewayLoginExplainsHowToFix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	// A gateway API key bills the same account but cannot name it, so it is
	// never the attribution for a reading.
	if err := os.WriteFile(path, []byte(`{"kilo":{"type":"api","key":"sk-gw"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pl := collect(t, path, subscribed(), nil, &KiloBalance{Balance: 1}, nil)
	if pl.Primary != nil || pl.Secondary != nil || pl.Tertiary != nil {
		t.Fatalf("an unnamed account produced windows: %+v", pl)
	}
	if pl.Source != "none" || pl.Note == nil || !strings.Contains(*pl.Note, "kilo auth login") {
		t.Fatalf("pl = %+v", pl)
	}
}

func TestCollectKiloLimits_AnUnpaidPlanIsNotMetered(t *testing.T) {
	// Kilo's own CLI treats only active/past_due/trialing as live; a cancelled
	// or unpaid plan has nothing left to meter.
	for _, status := range []string{"canceled", "incomplete", "unpaid", ""} {
		pass := subscribed()
		pass.Status = status
		pass.HasAllowanceParts = false
		pass.HasUsageParts = false
		pl := collect(t, kiloStore(t, "tok"), pass, nil, &KiloBalance{Balance: 3}, nil)
		if pl.Tertiary != nil {
			t.Fatalf("status %q produced a window: %+v", status, pl.Tertiary)
		}
		if pl.Note == nil {
			t.Fatalf("status %q has no note", status)
		}
		if status == "" {
			// An absent status is not a rejected status: the account simply has
			// no plan, which is the shared-balance case.
			if !strings.Contains(*pl.Note, "no Kilo Pass") {
				t.Fatalf("absent status note = %q", *pl.Note)
			}
			continue
		}
		if !strings.Contains(*pl.Note, status) || !strings.Contains(*pl.Note, "nothing left to meter") {
			t.Fatalf("status %q note = %q", status, *pl.Note)
		}
	}
}

func TestCollectKiloLimits_AHalfReportedPeriodDropsTheWindow(t *testing.T) {
	// A missing spend would read as an untouched period, which presents as a
	// full allowance. A missing allowance leaves only the bonus, which cannot
	// say what the plan was worth. Either half missing drops the bar.
	cases := map[string]*KiloPassState{
		"no spend":     {BaseCreditsUSD: 20, HasAllowanceParts: true},
		"no allowance": {UsageUSD: 3, HasUsageParts: true},
		"zero allowance": {
			BaseCreditsUSD: 0, UsageUSD: 3,
			HasAllowanceParts: true, HasUsageParts: true,
		},
		"negative spend": {
			BaseCreditsUSD: 20, UsageUSD: -5,
			HasAllowanceParts: true, HasUsageParts: true,
		},
	}
	for name, pass := range cases {
		pl := collect(t, kiloStore(t, "tok"), pass, nil, &KiloBalance{Balance: 1}, nil)
		if pl.Tertiary != nil {
			t.Fatalf("%s: window invented from an unusable ratio: %+v", name, pl.Tertiary)
		}
		if pl.Note == nil {
			t.Fatalf("%s: no note", name)
		}
		// One half named is a half-reported period; both halves named but the
		// ratio unusable is an unusable allowance. Both say so, neither bars.
		if !strings.Contains(*pl.Note, "only part of this period") &&
			!strings.Contains(*pl.Note, "no usable credit allowance") {
			t.Fatalf("%s: note = %q", name, *pl.Note)
		}
	}
}

func TestCollectKiloLimits_SpendingPastTheAllowanceIsFullyUsed(t *testing.T) {
	pass := subscribed()
	pass.UsageUSD = 44
	pl := collect(t, kiloStore(t, "tok"), pass, nil, &KiloBalance{}, nil)
	if pl.Tertiary == nil || pl.Tertiary.UsedPercentage != 100 {
		t.Fatalf("over-spend = %+v", pl.Tertiary)
	}
}

func TestCollectKiloLimits_ABalanceFailureStillExplainsTheQuota(t *testing.T) {
	// Losing the balance must not also lose the reason there is no bar.
	pl := collect(t, kiloStore(t, "tok"), &KiloPassState{}, nil, nil, errTest)
	if pl.Note == nil || !strings.Contains(*pl.Note, "balance unavailable") {
		t.Fatalf("note = %v", pl.Note)
	}
	if pl.Note == nil || !strings.Contains(*pl.Note, "no Kilo Pass") {
		t.Fatalf("note = %v", pl.Note)
	}
	if pl.Tertiary != nil {
		t.Fatalf("window invented: %+v", pl.Tertiary)
	}
}

func TestCollectKiloLimits_APassFailureIsReportedNotGuessed(t *testing.T) {
	pl := collect(t, kiloStore(t, "tok"), nil, errTest, &KiloBalance{Balance: 4}, nil)
	if pl.Source != "none" {
		t.Fatalf("source = %q", pl.Source)
	}
	if pl.Tertiary != nil {
		t.Fatalf("a failed fetch produced a window: %+v", pl.Tertiary)
	}
	if pl.Note == nil || !strings.Contains(*pl.Note, "could not be read") {
		t.Fatalf("note = %v", pl.Note)
	}
}

func TestCollectKiloLimits_TheCacheNeverServesAnotherAccountsReading(t *testing.T) {
	// The cache is keyed by the login's hashed identity. Two accounts on one
	// machine must never see each other's numbers, however recent the entry is.
	path := filepath.Join(t.TempDir(), "kilo-cache.json")
	t.Setenv("USAGEBAR_KILO_CACHE_PATH", path)
	first := kiloStore(t, "tok_first")
	second := kiloStore(t, "tok_second")

	// The same account moments later is served from the cache.
	CollectKiloLimits(nowMs, CollectKiloLimitsOptions{
		AuthPath:     first,
		FetchPass:    func(string) (*KiloPassState, error) { return subscribed(), nil },
		FetchBalance: func(string) (*KiloBalance, error) { return &KiloBalance{Balance: 9}, nil },
	})
	reused := CollectKiloLimits(nowMs+2000, CollectKiloLimitsOptions{
		AuthPath:     first,
		FetchPass:    func(string) (*KiloPassState, error) { t.Fatal("refetched a fresh entry"); return nil, nil },
		FetchBalance: func(string) (*KiloBalance, error) { t.Fatal("refetched a fresh entry"); return nil, nil },
	})
	if reused.Tertiary == nil {
		t.Fatalf("fresh cache entry not reused: %+v", reused)
	}

	// A different account must not inherit that entry, even though it is
	// milliseconds old.
	calls := 0
	pl := CollectKiloLimits(nowMs+3000, CollectKiloLimitsOptions{
		AuthPath: second,
		FetchPass: func(string) (*KiloPassState, error) {
			calls++
			return &KiloPassState{}, nil
		},
		FetchBalance: func(string) (*KiloBalance, error) { return &KiloBalance{Balance: 1}, nil },
	})
	if calls == 0 {
		t.Fatal("the second account was served the first account's cache entry")
	}
	if pl.Tertiary != nil {
		t.Fatalf("another account's window leaked: %+v", pl.Tertiary)
	}
}

func TestCollectKiloLimits_TheCachedFileNeverContainsTheCredential(t *testing.T) {
	// A stale cache file must not be able to leak a gateway login. What it does
	// store is the login's hashed identity, which is what makes the entry
	// refusable for a different account without keeping the secret on disk.
	path := filepath.Join(t.TempDir(), "kilo-cache.json")
	t.Setenv("USAGEBAR_KILO_CACHE_PATH", path)
	access := "super_secret_token_value"
	CollectKiloLimits(nowMs, CollectKiloLimitsOptions{
		AuthPath:     kiloStore(t, access),
		FetchPass:    func(string) (*KiloPassState, error) { return subscribed(), nil },
		FetchBalance: func(string) (*KiloBalance, error) { return &KiloBalance{Balance: 2}, nil },
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no cache file: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, access) {
		t.Fatalf("cache file carries the gateway token: %s", body)
	}
	for _, field := range []string{`"access"`, `"refresh"`, `"key"`} {
		if strings.Contains(body, field) {
			t.Fatalf("cache file carries credential field %s: %s", field, body)
		}
	}
	if !strings.Contains(body, kilo.CredentialID(access)) {
		t.Fatalf("cache file does not record the hashed identity: %s", body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestTheEndpointIsPinnedToTheOfficialHost(t *testing.T) {
	// A credential-bearing request must never follow a redirect away from the
	// host this collector chose, and KILO_API_URL must not move it.
	if kiloAPIURL != "https://api.kilo.ai" {
		t.Fatalf("kiloAPIURL = %q", kiloAPIURL)
	}
	client := kiloHTTPClient()
	if err := client.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirects are followed")
	}
	t.Setenv("KILO_API_URL", "https://evil.example")
	if kiloAPIURL != "https://api.kilo.ai" {
		t.Fatal("KILO_API_URL moved the endpoint")
	}
}

func TestJSONMoney_RejectsWhatCannotBeMeasured(t *testing.T) {
	for _, bad := range []any{nil, "", "abc", "-1", true, []int{1}} {
		if _, ok := jsonMoney(bad); ok {
			t.Fatalf("%v accepted as an amount", bad)
		}
	}
	if got, ok := jsonMoney(3.5); !ok || got != 3.5 {
		t.Fatalf("number = %v/%v", got, ok)
	}
	if got, ok := jsonMoney(" 20.00 "); !ok || got != 20 {
		t.Fatalf("numeric string = %v/%v", got, ok)
	}
}

var errTest = &testError{}

type testError struct{}

func (*testError) Error() string { return "network unreachable" }
