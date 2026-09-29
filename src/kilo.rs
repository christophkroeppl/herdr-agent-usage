//! Kilo Code's local stores: the gateway login and the session evidence.
//!
//! Kilo is an OpenCode fork, so its on-disk shapes are the same ones the
//! OpenCode reader handles: `auth.json` holds one entry per provider id, and
//! `kilo.db` keeps `session`/`message` plus the `session_v2`/`session_message`
//! pair newer sessions move to. The paths are Kilo's own — it never reads
//! OpenCode's store, and a machine with both installed keeps them apart.
//!
//! What Kilo does **not** have locally is quota. Its allowance lives behind
//! `providers::kilo`, which authenticates with the gateway login read here.

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Exact session-id lookup. Never a full-table scan.
const SESSION_BY_ID: &str = "SELECT id FROM session WHERE id = ?1 LIMIT 1";
/// Bounded same-session provider/model/token lookup. Not a spend scan.
const MESSAGE_DATA_FOR_SESSION: &str =
    "SELECT data FROM message WHERE session_id = ?1 ORDER BY time_created DESC LIMIT 8";
/// Kilo keeps new sessions in `session_v2` instead of `session`.
const SESSION_BY_ID_V2: &str = "SELECT id FROM session_v2 WHERE id = ?1 LIMIT 1";
/// The same bounded lookup against the v2 message table, which orders by the
/// session-unique `seq` and carries the role in `type` instead of the payload.
const MESSAGE_DATA_FOR_SESSION_V2: &str =
    "SELECT type, data FROM session_message WHERE session_id = ?1 ORDER BY seq DESC LIMIT 8";
/// A table this layout needs. Absent means the layout is not in use, not that
/// the store is unreadable.
const TABLE_BY_NAME: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1";
const MAX_MODELS_BYTES: u64 = 8 * 1024 * 1024;

/// One on-disk layout of Kilo's session store.
///
/// Kilo kept OpenCode's migration shape: `session`/`message` for sessions that
/// predate the v2 tables, `session_v2`/`session_message` for everything newer,
/// with the role moved out of the JSON payload into `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionSchema {
    sessions_table: &'static str,
    by_id: &'static str,
    messages: &'static str,
    role_in_column: bool,
}

/// Probed in order: a migrated session keeps the evidence it already had.
const SESSION_SCHEMAS: [SessionSchema; 2] = [
    SessionSchema {
        sessions_table: "session",
        by_id: SESSION_BY_ID,
        messages: MESSAGE_DATA_FOR_SESSION,
        role_in_column: false,
    },
    SessionSchema {
        sessions_table: "session_v2",
        by_id: SESSION_BY_ID_V2,
        messages: MESSAGE_DATA_FOR_SESSION_V2,
        role_in_column: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Api { has_secret: bool },
    Oauth,
}

impl CredentialKind {
    fn is_api_like(self) -> bool {
        matches!(self, Self::Api { .. })
    }
}

/// Kilo's credential kinds, keyed by provider id. Only the *shape* is kept:
/// the values stay in the file and are read on demand by the one caller that
/// has to send them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthMap {
    entries: BTreeMap<String, CredentialKind>,
}

impl AuthMap {
    pub fn get(&self, provider_id: &str) -> Option<CredentialKind> {
        self.entries.get(&provider_id.to_ascii_lowercase()).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthReadError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvidence {
    pub session_id: String,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub context_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLookup {
    Found(SessionEvidence),
    Missing,
    Unreadable,
}

#[derive(Debug, Clone)]
pub struct KiloPaths {
    pub auth: PathBuf,
    pub db: PathBuf,
    pub models: PathBuf,
}

impl KiloPaths {
    pub fn from_env() -> Option<Self> {
        let dir = kilo_data_dir()?;
        let cache = kilo_cache_dir()?;
        Some(Self {
            auth: dir.join("auth.json"),
            db: dir.join("kilo.db"),
            models: cache.join("models.json"),
        })
    }

    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            auth: dir.join("auth.json"),
            db: dir.join("kilo.db"),
            models: dir.join("models.json"),
        }
    }
}

fn kilo_cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("kilo"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".cache/kilo"))
}

fn kilo_data_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join("kilo"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share/kilo"))
}

/// The Kilo Gateway login Kilo keeps in its own credential store.
///
/// Only an OAuth device login counts. A gateway API key (`KILO_API_KEY`, or a
/// `kilo` entry of type `api`) is a different kind of principal: it bills the
/// same account but says nothing about *which* account, so it cannot attribute
/// a reading and is never used for one. The access token is read on demand and
/// never travels with a parsed map; the refresh token is not read, and this
/// plugin never exchanges or writes one.
pub struct GatewayCredential {
    pub access: String,
    /// Stable identity for cache scoping and for rejecting another login's
    /// cached reading.
    ///
    /// Hashed from the access token, the same stamp Cursor uses. Kilo rotates
    /// that token, so a rotation invalidates the cached snapshot and the next
    /// refresh re-reads it — conservative, never another account's numbers.
    pub account_id: String,
}

/// Reads the gateway login when the Kilo store has one.
///
/// A store without the entry, without a device login, or with a malformed
/// value yields `None`, which keeps the pane unattributed rather than
/// measured against whichever account happens to be signed in. Nothing here
/// logs.
pub fn gateway_credential(paths: &KiloPaths) -> Option<GatewayCredential> {
    let bytes = fs::read(&paths.auth).ok()?;
    parse_gateway_credential(&bytes)
}

fn parse_gateway_credential(bytes: &[u8]) -> Option<GatewayCredential> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let entry = value.get(GATEWAY_PROVIDER_ID)?.as_object()?;
    // `oauth` is the device login the CLI's own `/connect` flow writes. An
    // `api` entry is a gateway key, which this reader deliberately skips.
    if entry.get("type").and_then(Value::as_str) != Some("oauth") {
        return None;
    }
    let access = entry
        .get("access")
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if access.is_empty() {
        return None;
    }
    Some(GatewayCredential {
        account_id: crate::providers::credential_id(&access),
        access,
    })
}

/// The only Kilo subscription route: the Kilo Gateway itself.
///
/// Kilo serves other backends too (`openrouter`, `opencode-go`, …), and those
/// are billed elsewhere. A session on one of them owns no Kilo allowance.
pub const GATEWAY_PROVIDER_ID: &str = "kilo";

fn is_gateway_provider(provider_id: &str) -> bool {
    provider_id.trim().eq_ignore_ascii_case(GATEWAY_PROVIDER_ID)
}

pub fn read_auth(paths: &KiloPaths) -> Result<AuthMap, AuthReadError> {
    let bytes = fs::read(&paths.auth).map_err(|_| AuthReadError)?;
    parse_auth_json(&bytes)
}

pub fn parse_auth_json(bytes: &[u8]) -> Result<AuthMap, AuthReadError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AuthReadError)?;
    let object = value.as_object().ok_or(AuthReadError)?;
    let mut entries = BTreeMap::new();
    for (provider_id, entry) in object {
        let Some(kind) = credential_kind(entry) else {
            continue;
        };
        entries.insert(provider_id.to_ascii_lowercase(), kind);
    }
    Ok(AuthMap { entries })
}

fn credential_kind(entry: &Value) -> Option<CredentialKind> {
    let object = entry.as_object()?;
    match object.get("type").and_then(Value::as_str)? {
        "api" => Some(CredentialKind::Api {
            has_secret: non_empty_secret(object.get("key")),
        }),
        "oauth" => Some(CredentialKind::Oauth),
        _ => None,
    }
}

fn non_empty_secret(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|secret| !secret.is_empty())
}

pub fn lookup_session(paths: &KiloPaths, session_id: &str) -> SessionLookup {
    if session_id.is_empty() {
        return SessionLookup::Missing;
    }
    let Ok(connection) = open_readonly(&paths.db) else {
        return SessionLookup::Unreadable;
    };
    match read_session_evidence(&connection, session_id) {
        Ok(Some(evidence)) => SessionLookup::Found(evidence),
        Ok(None) => SessionLookup::Missing,
        Err(_) => SessionLookup::Unreadable,
    }
}

/// Reads the session from whichever store layout holds it. A layout whose
/// tables are absent is skipped: an older store has no v2 tables, and a
/// freshly upgraded one has no v2 rows for its older sessions.
fn read_session_evidence(
    connection: &Connection,
    session_id: &str,
) -> rusqlite::Result<Option<SessionEvidence>> {
    for schema in SESSION_SCHEMAS {
        if !table_exists(connection, schema.sessions_table)? {
            continue;
        }
        if !session_exists(connection, session_id, &schema)? {
            continue;
        }
        let (provider_id, model_id, context_tokens) =
            session_evidence(connection, session_id, &schema)?;
        return Ok(Some(SessionEvidence {
            session_id: session_id.to_string(),
            provider_id,
            model_id,
            context_tokens,
        }));
    }
    Ok(None)
}

fn table_exists(connection: &Connection, name: &str) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare(TABLE_BY_NAME)?;
    let mut rows = statement.query([name])?;
    Ok(rows.next()?.is_some())
}

fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
}

fn session_exists(
    connection: &Connection,
    session_id: &str,
    schema: &SessionSchema,
) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare(schema.by_id)?;
    let mut rows = statement.query([session_id])?;
    Ok(rows.next()?.is_some())
}

fn session_evidence(
    connection: &Connection,
    session_id: &str,
    schema: &SessionSchema,
) -> rusqlite::Result<(Option<String>, Option<String>, Option<u64>)> {
    let mut statement = connection.prepare(schema.messages)?;
    let mut rows = statement.query([session_id])?;
    let mut identity = None;
    while let Some(row) = rows.next()? {
        let role = schema
            .role_in_column
            .then(|| row.get::<_, String>(0))
            .transpose()?;
        let data: String = row.get(usize::from(schema.role_in_column))?;
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        let message_identity = provider_from_message(&value);
        if identity.is_none() {
            identity.clone_from(&message_identity);
        }
        if let (Some((provider_id, model_id)), Some(context_tokens)) = (
            message_identity,
            context_tokens_from_message(&value, role.as_deref()),
        ) {
            if identity.as_ref() == Some(&(provider_id, model_id)) {
                let (provider_id, model_id) = identity.unwrap();
                return Ok((Some(provider_id), model_id, Some(context_tokens)));
            }
        }
    }
    let (provider_id, model_id) = identity.unzip();
    Ok((provider_id, model_id.flatten(), None))
}

fn provider_from_message(value: &Value) -> Option<(String, Option<String>)> {
    let provider_id = string_field(value, "providerID")
        .or_else(|| {
            value
                .get("model")
                .and_then(|model| string_field(model, "providerID"))
        })?
        .trim()
        .to_string();
    if provider_id.is_empty() {
        return None;
    }
    // `modelID` is the v1 spelling; v2 nests the model under `model.id`.
    let model_id = string_field(value, "modelID").or_else(|| {
        value
            .get("model")
            .and_then(|model| string_field(model, "modelID").or_else(|| string_field(model, "id")))
    });
    Some((provider_id, model_id))
}

fn context_tokens_from_message(value: &Value, column_role: Option<&str>) -> Option<u64> {
    let role = value.get("role").and_then(Value::as_str).or(column_role);
    if role != Some("assistant") {
        return None;
    }
    let tokens = value.get("tokens")?;
    let output = token(tokens, "output");
    if output == 0 {
        return None;
    }
    let cache = tokens.get("cache").unwrap_or(&Value::Null);
    Some(
        token(tokens, "input")
            .saturating_add(output)
            .saturating_add(token(tokens, "reasoning"))
            .saturating_add(token(cache, "read"))
            .saturating_add(token(cache, "write")),
    )
}

fn token(value: &Value, name: &str) -> u64 {
    value.get(name).and_then(Value::as_u64).unwrap_or(0)
}

/// The context window Kilo's own model catalog publishes.
///
/// Kilo caches the catalog under its data dir with the same
/// `provider.models[model].limit.context` shape OpenCode uses, so this is the
/// same exact lookup against a different file.
pub fn model_context_window(paths: &KiloPaths, provider_id: &str, model_id: &str) -> Option<u64> {
    let mut bytes = Vec::new();
    fs::File::open(&paths.models)
        .ok()?
        .take(MAX_MODELS_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_MODELS_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get(provider_id)?
        .get("models")?
        .get(model_id)?
        .get("limit")?
        .get("context")?
        .as_u64()
        .filter(|window| *window > 0)
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Attribute a Kilo pane from its own session evidence.
///
/// Kilo runs several backends, so the pane's provider id is what decides, not
/// the fact that Kilo is running. A session on the Kilo Gateway resolves to
/// the Kilo subscription only when the store holds the gateway login that pays
/// for it; a session on any other backend with a key of its own is
/// [`Resolution::NoSubscription`], and anything unproven stays
/// [`Resolution::Indeterminate`].
pub fn classify_kilo(
    lookup: SessionLookup,
    auth: Result<&AuthMap, AuthReadError>,
) -> crate::model::Resolution {
    use crate::model::{BillingTarget, Resolution};

    let Ok(auth) = auth else {
        return Resolution::Indeterminate;
    };
    let SessionLookup::Found(session) = lookup else {
        return Resolution::Indeterminate;
    };
    let Some(provider_id) = session.provider_id.as_deref() else {
        return Resolution::Indeterminate;
    };

    if is_gateway_provider(provider_id) {
        return match auth.get(provider_id) {
            // The gateway login is the serving principal. Without it the pane
            // still runs on the Kilo Gateway, but nothing here can say whose
            // allowance it spends, so the pane keeps its prior state instead
            // of borrowing the signed-in account's numbers.
            Some(CredentialKind::Oauth) => Resolution::Subscription(BillingTarget::kilo_gateway()),
            _ => Resolution::Indeterminate,
        };
    }

    // For any other backend, an API-style key filed in Kilo's own auth.json
    // under that exact provider id is proof the session pays per token, or
    // through a plan this plugin cannot read. Either way it owns no Kilo quota,
    // so stale quota is cleared once. Missing credentials and unrecognised
    // entry shapes stay Indeterminate and keep prior metadata.
    match auth.get(provider_id) {
        Some(kind) if kind.is_api_like() => Resolution::NoSubscription,
        _ => Resolution::Indeterminate,
    }
}

#[cfg(test)]
pub(crate) fn write_fixture_db(path: &Path, rows: &[(&str, &str)]) -> rusqlite::Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "CREATE TABLE session (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL DEFAULT 'proj',
            slug TEXT NOT NULL DEFAULT 's',
            directory TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT 't',
            version TEXT NOT NULL DEFAULT '1',
            time_created INTEGER NOT NULL DEFAULT 1,
            time_updated INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE message (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            time_created INTEGER NOT NULL,
            time_updated INTEGER NOT NULL,
            data TEXT NOT NULL
        );",
    )?;
    for (index, (session_id, data)) in rows.iter().enumerate() {
        connection.execute(
            "INSERT INTO session (id) VALUES (?1)
             ON CONFLICT(id) DO NOTHING",
            [*session_id],
        )?;
        connection.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?3, ?4)",
            rusqlite::params![format!("msg_{index}"), *session_id, index as i64 + 1, *data],
        )?;
    }
    Ok(())
}

/// Kilo's v2 store layout. The role is a column there, so each row is
/// `(session id, type, data)`.
#[cfg(test)]
pub(crate) fn write_v2_fixture_db(
    path: &Path,
    rows: &[(&str, &str, &str)],
) -> rusqlite::Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "CREATE TABLE session_v2 (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL DEFAULT 'proj',
            slug TEXT NOT NULL DEFAULT 's',
            directory TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT 't',
            version TEXT NOT NULL DEFAULT '2',
            time_created INTEGER NOT NULL DEFAULT 1,
            time_updated INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE session_message (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            type TEXT NOT NULL,
            seq INTEGER,
            time_created INTEGER NOT NULL,
            time_updated INTEGER NOT NULL,
            data TEXT NOT NULL
        );",
    )?;
    for (index, (session_id, kind, data)) in rows.iter().enumerate() {
        connection.execute(
            "INSERT INTO session_v2 (id) VALUES (?1)
             ON CONFLICT(id) DO NOTHING",
            [*session_id],
        )?;
        connection.execute(
            "INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?4, ?4, ?5)",
            rusqlite::params![
                format!("msg_{index}"),
                *session_id,
                *kind,
                index as i64 + 1,
                *data
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Resolution;
    use tempfile::tempdir;

    const GATEWAY_LOGIN: &[u8] = br#"{
        "kilo": {"type":"oauth","refresh":"rt_secret","access":"st_access","expires":999},
        "openrouter": {"type":"api","key":"or_secret"}
    }"#;

    fn paths_in(directory: &Path) -> KiloPaths {
        KiloPaths {
            auth: directory.join("auth.json"),
            db: directory.join("kilo.db"),
            models: directory.join("models.json"),
        }
    }

    #[test]
    fn the_gateway_login_is_read_without_its_refresh_token() {
        let directory = tempdir().unwrap();
        let paths = paths_in(directory.path());
        fs::write(&paths.auth, GATEWAY_LOGIN).unwrap();
        let credential = gateway_credential(&paths).expect("gateway login");
        assert_eq!(credential.access, "st_access");
        assert_eq!(
            credential.account_id,
            crate::providers::credential_id("st_access")
        );
        // The identity carries no secret, and the refresh token is not read
        // at all: only `access` leaves this function.
        assert!(!credential.account_id.contains("st_access"));
        assert!(!credential.account_id.contains(&credential.access));
        assert!(!credential.account_id.contains("rt_secret"));
    }

    #[test]
    fn a_gateway_api_key_is_not_a_login() {
        // An `api` entry bills the same account but cannot name it, so it is
        // never used to attribute a reading.
        let directory = tempdir().unwrap();
        let paths = paths_in(directory.path());
        for entry in [
            br#"{"kilo":{"type":"api","key":"sk-gateway"}}"#.as_slice(),
            br#"{"kilo":{"type":"oauth","refresh":"rt","access":"   ","expires":1}}"#.as_slice(),
            br#"{"kilo":{"type":"oauth","refresh":"rt"}}"#.as_slice(),
            br#"{"openrouter":{"type":"api","key":"or"}}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            fs::write(&paths.auth, entry).unwrap();
            assert!(
                gateway_credential(&paths).is_none(),
                "accepted {}",
                String::from_utf8_lossy(entry)
            );
        }
    }

    #[test]
    fn a_missing_store_has_no_credential() {
        let directory = tempdir().unwrap();
        assert!(gateway_credential(&paths_in(directory.path())).is_none());
    }

    #[test]
    fn a_gateway_session_with_a_login_resolves_to_the_kilo_subscription() {
        let directory = tempdir().unwrap();
        let db = directory.path().join("kilo.db");
        write_fixture_db(
            &db,
            &[(
                "ses_kilo",
                r#"{"role":"assistant","providerID":"kilo","modelID":"stealth/space-bunny-alpha"}"#,
            )],
        )
        .unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, GATEWAY_LOGIN).unwrap();
        let lookup = lookup_session(&paths, "ses_kilo");
        let auth = read_auth(&paths).unwrap();
        assert_eq!(
            classify_kilo(lookup, Ok(&auth)),
            Resolution::Subscription(crate::model::BillingTarget::kilo_gateway())
        );
    }

    #[test]
    fn a_gateway_session_without_the_login_is_never_measured_against_whoever_signed_in() {
        let directory = tempdir().unwrap();
        let db = directory.path().join("kilo.db");
        write_fixture_db(
            &db,
            &[("ses_kilo", r#"{"role":"assistant","providerID":"kilo"}"#)],
        )
        .unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, br#"{"openrouter":{"type":"api","key":"or"}}"#).unwrap();
        let lookup = lookup_session(&paths, "ses_kilo");
        let auth = read_auth(&paths).unwrap();
        assert_eq!(classify_kilo(lookup, Ok(&auth)), Resolution::Indeterminate);

        // An unreadable store is the same answer, not a guess.
        fs::write(&paths.auth, b"{not json").unwrap();
        let lookup = lookup_session(&paths, "ses_kilo");
        assert_eq!(
            classify_kilo(lookup, Err(AuthReadError)),
            Resolution::Indeterminate
        );
    }

    #[test]
    fn two_sessions_on_different_accounts_keep_separate_quota() {
        // The attribution identity is the login, not the harness: a store
        // swapped for another account's produces a different target, so the
        // first account's cached reading can never answer for the second.
        let first_dir = fixture_store("ses_kilo", br#"{"kilo":{"type":"oauth","access":"tok_a"}}"#);
        let second_dir =
            fixture_store("ses_kilo", br#"{"kilo":{"type":"oauth","access":"tok_b"}}"#);
        let first = KiloPaths::from_dir(first_dir.path());
        let second = KiloPaths::from_dir(second_dir.path());
        let a = gateway_credential(&first).unwrap();
        let b = gateway_credential(&second).unwrap();
        assert_ne!(a.account_id, b.account_id);
        // One cache file for the store, one account marker on the reading: the
        // second login cannot read the first one's snapshot.
        let cached = crate::model::ProviderSnapshot::new(
            crate::model::Provider::Kilo,
            vec![
                crate::model::UsageWindow::new(crate::model::WindowKind::Monthly, 42.0, None)
                    .unwrap(),
            ],
            0,
        )
        .with_account_id(Some(a.account_id.clone()));
        assert!(!cached.usable_for_account(Some(&b.account_id), Some(1)));
        assert!(cached.usable_for_account(Some(&a.account_id), Some(1)));
    }

    #[test]
    fn another_backend_with_its_own_key_owns_no_kilo_quota() {
        let directory = tempdir().unwrap();
        let db = directory.path().join("kilo.db");
        write_fixture_db(
            &db,
            &[(
                "ses_or",
                r#"{"role":"assistant","providerID":"openrouter","modelID":"some/model"}"#,
            )],
        )
        .unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, GATEWAY_LOGIN).unwrap();
        let lookup = lookup_session(&paths, "ses_or");
        let auth = read_auth(&paths).unwrap();
        assert_eq!(classify_kilo(lookup, Ok(&auth)), Resolution::NoSubscription);
    }

    #[test]
    fn another_backend_without_a_key_is_indeterminate() {
        let directory = tempdir().unwrap();
        let db = directory.path().join("kilo.db");
        write_fixture_db(
            &db,
            &[(
                "ses_x",
                r#"{"role":"assistant","providerID":"some-fresh-backend"}"#,
            )],
        )
        .unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, GATEWAY_LOGIN).unwrap();
        let lookup = lookup_session(&paths, "ses_x");
        let auth = read_auth(&paths).unwrap();
        assert_eq!(classify_kilo(lookup, Ok(&auth)), Resolution::Indeterminate);
    }

    #[test]
    fn a_missing_or_unreadable_session_is_never_attributed() {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, GATEWAY_LOGIN).unwrap();
        write_fixture_db(&paths.db, &[]).unwrap();
        let auth = read_auth(&paths).unwrap();
        assert_eq!(
            classify_kilo(lookup_session(&paths, "ses_absent"), Ok(&auth)),
            Resolution::Indeterminate
        );
        assert_eq!(
            classify_kilo(lookup_session(&paths, ""), Ok(&auth)),
            Resolution::Indeterminate
        );

        fs::write(&paths.db, b"this is not a sqlite database").unwrap();
        assert_eq!(
            classify_kilo(lookup_session(&paths, "ses_kilo"), Ok(&auth)),
            Resolution::Indeterminate
        );
    }

    #[test]
    fn the_latest_completed_assistant_message_carries_the_context() {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        write_fixture_db(
            &paths.db,
            &[
                (
                    "ses_context",
                    r#"{"role":"assistant","providerID":"kilo","modelID":"space-bunny","tokens":{"input":100,"output":10,"reasoning":5,"cache":{"read":20,"write":30}}}"#,
                ),
                (
                    "ses_context",
                    r#"{"role":"assistant","providerID":"kilo","modelID":"space-bunny","tokens":{"input":999,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}}"#,
                ),
            ],
        )
        .unwrap();
        match lookup_session(&paths, "ses_context") {
            SessionLookup::Found(session) => {
                assert_eq!(session.provider_id.as_deref(), Some("kilo"));
                assert_eq!(session.model_id.as_deref(), Some("space-bunny"));
                assert_eq!(session.context_tokens, Some(165));
            }
            other => panic!("expected found session, got {other:?}"),
        }
    }

    #[test]
    fn a_v2_session_reads_the_role_column_and_the_model_object() {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        write_v2_fixture_db(
            &paths.db,
            &[
                (
                    "ses_v2",
                    "user",
                    r#"{"model":{"id":"space-bunny","providerID":"kilo"}}"#,
                ),
                (
                    "ses_v2",
                    "assistant",
                    r#"{"model":{"id":"space-bunny","providerID":"kilo"},"tokens":{"input":100,"output":10,"reasoning":5,"cache":{"read":20,"write":30}}}"#,
                ),
            ],
        )
        .unwrap();
        match lookup_session(&paths, "ses_v2") {
            SessionLookup::Found(session) => {
                assert_eq!(session.provider_id.as_deref(), Some("kilo"));
                assert_eq!(session.context_tokens, Some(165));
            }
            other => panic!("expected found session, got {other:?}"),
        }
    }

    #[test]
    fn a_migrated_session_keeps_the_evidence_it_already_had() {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        write_fixture_db(
            &paths.db,
            &[(
                "ses_both",
                r#"{"role":"assistant","providerID":"openrouter"}"#,
            )],
        )
        .unwrap();
        write_v2_fixture_db(
            &paths.db,
            &[(
                "ses_both",
                "assistant",
                r#"{"model":{"id":"x","providerID":"kilo"}}"#,
            )],
        )
        .unwrap();
        match lookup_session(&paths, "ses_both") {
            SessionLookup::Found(session) => {
                assert_eq!(session.provider_id.as_deref(), Some("openrouter"));
            }
            other => panic!("expected found session, got {other:?}"),
        }
    }

    #[test]
    fn model_context_lookup_is_exact_and_bounded() {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(
            &paths.models,
            br#"{"kilo":{"models":{"space-bunny":{"limit":{"context":1000000}}}},"other":{"models":{"space-bunny":{"limit":{"context":1}}}}}"#,
        )
        .unwrap();
        assert_eq!(
            model_context_window(&paths, "kilo", "space-bunny"),
            Some(1_000_000)
        );
        assert_eq!(model_context_window(&paths, "kilo", "missing"), None);
        assert_eq!(
            model_context_window(&paths, "other", "space-bunny"),
            Some(1)
        );

        fs::write(&paths.models, vec![b' '; MAX_MODELS_BYTES as usize + 1]).unwrap();
        assert_eq!(model_context_window(&paths, "kilo", "space-bunny"), None);
    }

    #[test]
    fn the_auth_map_records_kind_without_keeping_secrets() {
        let auth = parse_auth_json(GATEWAY_LOGIN).unwrap();
        assert_eq!(auth.get("kilo"), Some(CredentialKind::Oauth));
        assert_eq!(
            auth.get("openrouter"),
            Some(CredentialKind::Api { has_secret: true })
        );
        assert!(!format!("{auth:?}").contains("or_secret"));
        assert_eq!(auth.get("absent"), None);
    }

    #[test]
    fn malformed_auth_is_an_error() {
        assert!(parse_auth_json(b"{not json").is_err());
        assert!(parse_auth_json(b"[1]").is_err());
    }

    #[test]
    fn queries_are_exact_session_lookups() {
        assert!(SESSION_BY_ID.contains("WHERE id = ?1"));
        assert!(MESSAGE_DATA_FOR_SESSION.contains("WHERE session_id = ?1"));
        assert!(MESSAGE_DATA_FOR_SESSION.contains("LIMIT 8"));
        assert!(!MESSAGE_DATA_FOR_SESSION.contains("SUM("));
        assert!(MESSAGE_DATA_FOR_SESSION_V2.contains("WHERE session_id = ?1"));
        assert!(MESSAGE_DATA_FOR_SESSION_V2.contains("LIMIT 8"));
        assert!(!MESSAGE_DATA_FOR_SESSION_V2.contains("SUM("));
    }

    /// A whole Kilo store for one account: its login and one gateway session.
    fn fixture_store(session_id: &str, auth: &[u8]) -> tempfile::TempDir {
        let directory = tempdir().unwrap();
        let paths = KiloPaths::from_dir(directory.path());
        fs::write(&paths.auth, auth).unwrap();
        write_fixture_db(
            &paths.db,
            &[(
                session_id,
                r#"{"role":"assistant","providerID":"kilo","modelID":"space-bunny"}"#,
            )],
        )
        .unwrap();
        directory
    }
}
