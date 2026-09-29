//! Kilo Code's Kilo Pass allowance.
//!
//! Kilo has no rolling 5h or 7d bucket. Its subscription is a monthly credit
//! allowance, and it is the only allowance Kilo publishes for a signed-in
//! account, so this collector produces one [`WindowKind::Monthly`] window and
//! nothing else. A pane with no monthly window shows no quota rather than a
//! fabricated short window — see `providers::opencode_go` for a source that
//! does have 5h/7d/30d.
//!
//! The reading is the account's own Kilo Pass state:
//! `GET {KILO_API_URL}/api/trpc/kiloPass.getState`, the same tRPC procedure the
//! CLI calls for the "Kilo Pass" line in its account panel, authenticated with
//! the OAuth device login Kilo keeps in `auth.json`. That login is the serving
//! principal for a pane whose session names the `kilo` provider, so the reading
//! is stamped with that login's identity and a different account's cached value
//! can never answer for it.
//!
//! Two payloads answer "no meter", both of them normal:
//!
//! 1. `subscription: null` — the account pays from a shared credit balance
//!    instead of a plan. [`crate::providers::kilo`] has no balance window: the
//!    balance endpoint reports a dollar amount with no limit attached, and a
//!    percentage invented from it would be a guess.
//! 2. A status outside the CLI's own set (`active`, `past_due`, `trialing`) —
//!    a cancelled or unpaid plan has nothing left to meter.
//!
//! Everything fails closed: a missing, malformed, or unexpected field drops the
//! window instead of reading as 0% used, and a request failure is an error, so
//! the caller keeps the last good reading for this same account.

use crate::cache::CacheStore;
use crate::kilo::GatewayCredential;
use crate::model::{Provider, ProviderSnapshot, ResetAt, UsageWindow, WindowKind};
use crate::providers::ProviderError;
use anyhow::{Context, Result};
use serde_json::Value;
use std::time::Duration;

/// Official host and path. The credential is only ever sent here; a redirect
/// away from this host drops the request rather than following it.
///
/// Kilo lets `KILO_API_URL` move the API host for its own runs. This collector
/// does not honour it: an account's allowance lives on the official control
/// plane, and a configured override that pointed somewhere else would send the
/// login to a host this plugin cannot vouch for.
const KILO_PASS_URL: &str = "https://api.kilo.ai/api/trpc/kiloPass.getState";

/// tRPC batch envelope for a single zero-argument procedure.
const KILO_PASS_QUERY: &str = "batch=1&input=%7B%220%22%3Anull%7D";

/// Statuses the CLI itself treats as a live subscription. A status outside this
/// set is not metered: the plan is not paying for the session.
const LIVE_STATUSES: [&str; 3] = ["active", "past_due", "trialing"];

pub fn fetch(credential: &GatewayCredential) -> Result<ProviderSnapshot> {
    let access = credential.access.trim();
    if access.is_empty() {
        return Err(ProviderError::MissingCredentials.into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(10))
        .timeout_write(Duration::from_secs(10))
        // A credential-bearing request must not be replayed to another host.
        .redirects(0)
        .build();
    let response = agent
        .get(&format!("{KILO_PASS_URL}?{KILO_PASS_QUERY}"))
        .set("Authorization", &format!("Bearer {access}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|error| ProviderError::Request(http_error_status(&error)))?;
    let value: Value = response.into_json().context("decode Kilo Pass response")?;
    parse_pass_state(&value, CacheStore::now_unix())
        .map(|snapshot| snapshot.with_account_id(Some(credential.account_id.clone())))
        .map_err(anyhow::Error::from)
}

/// Build a snapshot from the account's Kilo Pass state.
///
/// The tRPC envelope is unwrapped exactly the way the CLI unwraps it: a batch
/// reply is an array, `result.data` holds the payload, and a single-object reply
/// with no `json` wrapper is the payload itself. Any other shape is an error
/// rather than a reading.
pub fn parse_pass_state(value: &Value, now_unix: u64) -> Result<ProviderSnapshot, ProviderError> {
    let subscription = pass_state(value).ok_or_else(|| {
        ProviderError::UnsupportedResponse("missing kiloPass subscription".to_string())
    })?;
    if let Some(status) = subscription.get("status").and_then(Value::as_str) {
        if !LIVE_STATUSES.contains(&status) {
            return Err(ProviderError::UnsupportedResponse(format!(
                "kiloPass status is {status}"
            )));
        }
    }

    // A meter needs both halves of its ratio. The CLI drops the reading unless
    // one of the two amounts is present; this is stricter, because a missing
    // spend reads as an untouched period and a missing allowance leaves only
    // the bonus, which cannot say what the plan was worth. Either half missing
    // drops the window rather than presenting as a full allowance.
    let used = usd(subscription.get("currentPeriodUsageUsd")).ok_or_else(|| {
        ProviderError::UnsupportedResponse("missing kiloPass current-period usage".to_string())
    })?;
    let base = usd(subscription.get("currentPeriodBaseCreditsUsd")).ok_or_else(|| {
        ProviderError::UnsupportedResponse("missing kiloPass current-period allowance".to_string())
    })?;
    // Bonus credits are granted into the same period and expire with it, so
    // they are allowance, not a top-up outside the window. A plan with none
    // reads as its base alone.
    let bonus = usd(subscription.get("currentPeriodBonusCreditsUsd")).unwrap_or(0.0);
    let limit = base + bonus;
    if limit <= 0.0 {
        return Err(ProviderError::UnsupportedResponse(
            "kiloPass current-period allowance is not positive".to_string(),
        ));
    }
    let used_percent = (used / limit * 100.0).clamp(0.0, 100.0);
    let reset = subscription
        .get("nextBillingAt")
        .or_else(|| subscription.get("nextRenewalAt"))
        .and_then(Value::as_str)
        .and_then(ResetAt::parse);

    let window = UsageWindow::new(WindowKind::Monthly, used_percent, reset)
        .map_err(|error| ProviderError::UnsupportedResponse(error.to_string()))?;
    Ok(ProviderSnapshot::new(
        Provider::Kilo,
        vec![window],
        now_unix,
    ))
}

/// The `subscription` object, through whichever tRPC envelope it arrives in.
///
/// Returns `None` for an account on a shared balance instead of a plan — the
/// same "no subscription" the CLI reads, and the case that must degrade quietly
/// rather than show a number.
fn pass_state(value: &Value) -> Option<&Value> {
    let root = match value {
        Value::Array(items) => items.first()?,
        other => other,
    };
    let data = root.get("result")?.get("data")?;
    let payload = data.get("json").unwrap_or(data);
    let subscription = payload.get("subscription")?;
    subscription.is_object().then_some(subscription)
}

/// Kilo sends these amounts as JSON numbers in US dollars; a string spelling is
/// accepted because the same value has been spelled both ways upstream. A
/// non-finite or negative amount is not a reading.
fn usd(value: Option<&Value>) -> Option<f64> {
    let amount = match value? {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    (amount.is_finite() && amount >= 0.0).then_some(amount)
}

/// Never let an auth or transport failure reach the cache as a quota value.
/// The caller keeps the last good snapshot for this same account instead.
fn http_error_status(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Status(401 | 403, _) => "HTTP 401/403 (invalid credentials)".to_string(),
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(error) => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_787_000_000;

    /// The deployed shape, with the amounts kept as the API sends them: JSON
    /// numbers in US dollars. `batch=1` replies as a one-item array.
    fn subscribed() -> Value {
        json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 20.0,
            "currentPeriodUsageUsd": 3.42,
            "currentPeriodBonusCreditsUsd": 10.0,
            "nextBillingAt": "2026-10-11T10:09:35.000Z",
            "status": "active"
        }}}}])
    }

    #[test]
    fn a_pass_account_reads_one_monthly_window() {
        let snapshot = parse_pass_state(&subscribed(), NOW).unwrap();
        assert_eq!(snapshot.provider, Provider::Kilo);
        assert_eq!(snapshot.source, Provider::Kilo.source());
        assert_eq!(snapshot.windows.len(), 1);
        let month = snapshot.window(WindowKind::Monthly).unwrap();
        // 3.42 of a 30.00 allowance (20 base + 10 bonus).
        assert!((month.used_percent - 11.4).abs() < 0.01);
        assert!((month.remaining_percent - 88.6).abs() < 0.01);
        assert_eq!(month.resets_at, ResetAt::parse("2026-10-11T10:09:35.000Z"));
    }

    /// Kilo has no 5h or 7d bucket, so neither token may ever appear for a
    /// Kilo pane. A monthly-only reading is the shape, not a gap.
    #[test]
    fn kilo_publishes_no_short_windows() {
        let snapshot = parse_pass_state(&subscribed(), NOW).unwrap();
        assert!(snapshot.window(WindowKind::FiveHour).is_none());
        assert!(snapshot.window(WindowKind::Weekly).is_none());
    }

    #[test]
    fn an_account_on_a_shared_balance_degrades_quietly() {
        // What Kilo actually answers for an account with no plan: HTTP 200 and
        // a null subscription. That is not an error to surface and not a 0%.
        let free = json!([{"result": {"data": {
            "subscription": null,
            "isEligibleForFirstMonthPromo": false
        }}}]);
        assert!(parse_pass_state(&free, NOW).is_err());
    }

    #[test]
    fn a_plan_that_is_not_paying_yet_is_not_metered() {
        for status in ["canceled", "incomplete", "unpaid", ""] {
            let value = json!([{"result": {"data": {"subscription": {
                "currentPeriodBaseCreditsUsd": 20.0,
                "currentPeriodUsageUsd": 1.0,
                "status": status
            }}}}]);
            assert!(parse_pass_state(&value, NOW).is_err(), "accepted {status}");
        }
        // An absent status is not a rejected status.
        let unstated = json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 20.0,
            "currentPeriodUsageUsd": 1.0
        }}}}]);
        assert!(parse_pass_state(&unstated, NOW).is_ok());
    }

    #[test]
    fn a_plan_without_bonus_credits_reads_against_its_base() {
        let value = json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 20.0,
            "currentPeriodUsageUsd": 5.0,
            "currentPeriodBonusCreditsUsd": 0.0,
            "nextRenewalAt": "2026-10-01T00:00:00.000Z",
            "status": "trialing"
        }}}}]);
        let snapshot = parse_pass_state(&value, NOW).unwrap();
        let month = snapshot.window(WindowKind::Monthly).unwrap();
        assert!((month.used_percent - 25.0).abs() < 0.01);
        assert_eq!(month.resets_at, ResetAt::parse("2026-10-01T00:00:00.000Z"));
    }

    #[test]
    fn the_envelope_is_unwrapped_the_way_the_cli_unwraps_it() {
        // Single-object reply with no batch array.
        let bare = json!({"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 10.0,
            "currentPeriodUsageUsd": 5.0
        }}}, });
        assert!(parse_pass_state(&bare, NOW).is_ok());
        // `json` wrapper inside `result.data`.
        let wrapped = json!([{"result": {"data": {"json": {"subscription": {
            "currentPeriodBaseCreditsUsd": 10.0,
            "currentPeriodUsageUsd": 5.0
        }}}}}]);
        assert!(parse_pass_state(&wrapped, NOW).is_ok());
    }

    #[test]
    fn every_unknown_shape_fails_closed() {
        for payload in [
            json!({}),
            json!([]),
            json!(null),
            json!([{"error": {"json": {"message": "unauthorized"}}}]),
            json!([{"result": {"data": {}}}]),
            json!([{"result": {"data": {"subscription": {}}}}]),
            json!([{"result": {"data": {"subscription": []}}}]),
            json!([{"result": {"data": {"subscription": {
                "currentPeriodBaseCreditsUsd": 0.0,
                "currentPeriodUsageUsd": 4.0
            }}}}]),
            json!([{"result": {"data": {"subscription": {
                "currentPeriodBaseCreditsUsd": "lots",
                "currentPeriodUsageUsd": 1.0
            }}}}]),
            json!([{"result": {"data": {"subscription": {
                "currentPeriodBaseCreditsUsd": -20.0,
                "currentPeriodUsageUsd": 1.0
            }}}}]),
        ] {
            assert!(
                parse_pass_state(&payload, NOW).is_err(),
                "accepted {payload}"
            );
        }
    }

    /// A missing allowance must never read as a full one, and a missing usage
    /// must never read as an untouched period.
    #[test]
    fn a_half_reported_period_drops_the_window_rather_than_defaulting_it() {
        let no_usage = json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 20.0
        }}}}]);
        assert!(parse_pass_state(&no_usage, NOW).is_err());

        let no_allowance = json!([{"result": {"data": {"subscription": {
            "currentPeriodUsageUsd": 3.0
        }}}}]);
        assert!(parse_pass_state(&no_allowance, NOW).is_err());

        // Bonus alone with no base is not an allowance either.
        let bonus_only = json!([{"result": {"data": {"subscription": {
            "currentPeriodBonusCreditsUsd": 10.0,
            "currentPeriodUsageUsd": 3.0
        }}}}]);
        assert!(parse_pass_state(&bonus_only, NOW).is_err());
    }

    #[test]
    fn amounts_are_accepted_as_strings_too_and_clamped_not_trusted() {
        let strings = json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": "20.00",
            "currentPeriodUsageUsd": "3.42",
            "currentPeriodBonusCreditsUsd": "0"
        }}}}]);
        let snapshot = parse_pass_state(&strings, NOW).unwrap();
        assert!((snapshot.window(WindowKind::Monthly).unwrap().used_percent - 17.1).abs() < 0.01);

        // Spending past the allowance is 100% used, not a negative remainder.
        let over = json!([{"result": {"data": {"subscription": {
            "currentPeriodBaseCreditsUsd": 20.0,
            "currentPeriodUsageUsd": 44.0
        }}}}]);
        let snapshot = parse_pass_state(&over, NOW).unwrap();
        let month = snapshot.window(WindowKind::Monthly).unwrap();
        assert_eq!(month.used_percent, 100.0);
        assert_eq!(month.remaining_percent, 0.0);
    }

    #[test]
    fn credentials_never_appear_in_an_error() {
        let credential = GatewayCredential {
            access: "   ".to_string(),
            account_id: "acct".to_string(),
        };
        let error = fetch(&credential).unwrap_err().to_string();
        assert!(error.contains("credentials"), "{error}");
    }

    #[test]
    fn every_transport_and_status_failure_maps_to_an_error_not_a_quota_value() {
        let rate_limited = http_error_status(&ureq::Error::Status(
            429,
            ureq::Response::new(429, "Too Many Requests", "").unwrap(),
        ));
        assert_eq!(rate_limited, "HTTP 429");

        for code in [401, 403] {
            let status = http_error_status(&ureq::Error::Status(
                code,
                ureq::Response::new(code, "denied", "").unwrap(),
            ));
            assert!(status.contains("invalid credentials"), "{code}: {status}");
        }

        for code in [400, 429, 500, 503] {
            let status = http_error_status(&ureq::Error::Status(
                code,
                ureq::Response::new(code, "x", "").unwrap(),
            ));
            assert!(!status.contains('%'), "{code}: {status}");
        }
    }

    #[test]
    fn the_endpoint_is_the_official_host_only() {
        assert!(KILO_PASS_URL.starts_with("https://api.kilo.ai/api/trpc/"));
        assert_eq!(
            KILO_PASS_URL,
            format!("https://api.kilo.ai/api/trpc/kiloPass.getState")
        );
        // The procedure is named in the URL and the query carries only the
        // zero-argument envelope: no account id travels in the request.
        assert!(KILO_PASS_QUERY.contains("%220%22"));
    }
}
