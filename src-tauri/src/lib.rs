use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};

const KEYCHAIN_SERVICE: &str = "Singra Vault";
const REFRESH_TOKEN_ACCOUNT: &str = "active-refresh-token";
const PKCE_VERIFIER_ACCOUNT: &str = "active-pkce-verifier";
const LOCAL_SECRET_ACCOUNT_PREFIX: &str = "local-secret::";
const DEVICE_KEY_LOCAL_SECRET_PREFIX: &str = "device-key:";
const INTEGRITY_LOCAL_SECRET_PREFIX: &str = "vault-integrity:";
const PKCE_VERIFIER_MAX_AGE_MS: u128 = 10 * 60 * 1000;
const SINGLE_INSTANCE_DEEP_LINK_EVENT: &str = "singra://deep-link";
const TAURI_OAUTH_CALLBACK_PREFIX: &str = "singravault://auth/callback";

#[derive(Serialize, Deserialize)]
struct PkceVerifierRecord {
    key: String,
    verifier: String,
    created_at_ms: u128,
}

#[derive(Serialize, Deserialize, Clone)]
struct PkceVerifierStoreEntry {
    verifier: String,
    created_at_ms: u128,
}

type PkceVerifierStore = HashMap<String, PkceVerifierStoreEntry>;

#[tauri::command]
fn save_refresh_token(refresh_token: String) -> Result<(), String> {
    let token = refresh_token.trim();
    if token.is_empty() {
        return Err("refresh token must not be empty".to_string());
    }

    keychain_entry()?.set_password(token).map_err(keyring_error)
}

#[tauri::command]
fn load_refresh_token() -> Result<Option<String>, String> {
    match keychain_entry()?.get_password() {
        Ok(token) if token.trim().is_empty() => Ok(None),
        Ok(token) => Ok(Some(token)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

#[tauri::command]
fn clear_refresh_token() -> Result<(), String> {
    match keychain_entry()?.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => Err(keyring_error(error)),
    }
}

#[tauri::command]
fn save_pkce_verifier(key: String, verifier: String) -> Result<(), String> {
    let key = key.trim();
    let verifier = verifier.trim();
    if key.is_empty() {
        return Err("PKCE verifier key must not be empty".to_string());
    }
    if verifier.is_empty() {
        return Err("PKCE verifier must not be empty".to_string());
    }

    let mut store = load_pkce_store()?;
    store.insert(key.to_string(), PkceVerifierStoreEntry {
        verifier: verifier.to_string(),
        created_at_ms: now_millis()?,
    });
    save_pkce_store(&store)
}

#[tauri::command]
fn load_pkce_verifier(key: String) -> Result<Option<String>, String> {
    let requested_key = key.trim();
    if requested_key.is_empty() {
        return Ok(None);
    }

    let mut store = load_pkce_store()?;
    let removed_expired = prune_expired_pkce_entries(&mut store)?;
    let value = store
        .get(requested_key)
        .map(|record| record.verifier.trim().to_string())
        .filter(|verifier| !verifier.is_empty());

    if removed_expired {
        save_pkce_store(&store)?;
    }

    Ok(value)
}

#[tauri::command]
fn clear_pkce_verifier(key: String) -> Result<(), String> {
    let requested_key = key.trim();
    if requested_key.is_empty() {
        return Ok(());
    }

    let mut store = load_pkce_store()?;
    store.remove(requested_key);
    save_pkce_store(&store)
}

#[tauri::command]
fn save_local_secret(key: String, value: String) -> Result<(), String> {
    let entry = local_secret_entry(&key)?;
    let trimmed_value = value.trim();
    if trimmed_value.is_empty() {
        return Err("local secret value must not be empty".to_string());
    }

    entry.set_password(trimmed_value).map_err(keyring_error)
}

#[tauri::command]
fn load_local_secret(key: String) -> Result<Option<String>, String> {
    let entry = local_secret_entry(&key)?;
    match entry.get_password() {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

#[tauri::command]
fn clear_local_secret(key: String) -> Result<(), String> {
    let entry = local_secret_entry(&key)?;
    match entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => Err(keyring_error(error)),
    }
}

fn keychain_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, REFRESH_TOKEN_ACCOUNT).map_err(keyring_error)
}

fn pkce_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, PKCE_VERIFIER_ACCOUNT).map_err(keyring_error)
}

fn local_secret_entry(key: &str) -> Result<Entry, String> {
    let normalized_key = normalize_local_secret_key(key)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{normalized_key}");
    Entry::new(KEYCHAIN_SERVICE, &account).map_err(keyring_error)
}

fn normalize_local_secret_key(key: &str) -> Result<String, String> {
    let normalized_key = key.trim();

    if is_allowed_user_scoped_secret_key(normalized_key, DEVICE_KEY_LOCAL_SECRET_PREFIX)
        || is_allowed_user_scoped_secret_key(normalized_key, INTEGRITY_LOCAL_SECRET_PREFIX)
    {
        return Ok(normalized_key.to_string());
    }

    Err("local secret key is not allowed".to_string())
}

fn is_allowed_user_scoped_secret_key(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .map(is_uuid_like)
        .unwrap_or(false)
}

fn is_uuid_like(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }

    for (index, character) in value.chars().enumerate() {
        let should_be_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if should_be_hyphen {
            if character != '-' {
                return false;
            }
        } else if !character.is_ascii_hexdigit() {
            return false;
        }
    }

    // Supabase auth user ids are UUID v4. Requiring the version and variant
    // keeps renderer-accessible keychain accounts tightly user-scoped instead
    // of accepting arbitrary UUID-looking names.
    value.as_bytes()[14] == b'4'
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

fn load_pkce_store() -> Result<PkceVerifierStore, String> {
    let payload = match pkce_entry()?.get_password() {
        Ok(payload) if payload.trim().is_empty() => return Ok(HashMap::new()),
        Ok(payload) => payload,
        Err(KeyringError::NoEntry) => return Ok(HashMap::new()),
        Err(error) => return Err(keyring_error(error)),
    };

    match serde_json::from_str::<PkceVerifierStore>(&payload) {
        Ok(store) => Ok(store),
        Err(_) => match serde_json::from_str::<PkceVerifierRecord>(&payload) {
            Ok(record) => {
                let mut store = HashMap::new();
                store.insert(record.key, PkceVerifierStoreEntry {
                    verifier: record.verifier,
                    created_at_ms: record.created_at_ms,
                });
                Ok(store)
            }
            Err(_) => {
                let _ = pkce_entry()?.delete_credential();
                Ok(HashMap::new())
            }
        },
    }
}

fn save_pkce_store(store: &PkceVerifierStore) -> Result<(), String> {
    if store.is_empty() {
        return match pkce_entry()?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(error)),
        };
    }

    let payload = serde_json::to_string(store)
        .map_err(|error| format!("PKCE verifier serialization failed: {error}"))?;

    pkce_entry()?.set_password(&payload).map_err(keyring_error)
}

fn prune_expired_pkce_entries(store: &mut PkceVerifierStore) -> Result<bool, String> {
    let mut expired_keys = Vec::new();

    for (key, entry) in store.iter() {
        if is_pkce_record_expired(entry.created_at_ms)? {
            expired_keys.push(key.clone());
        }
    }

    let had_expired_keys = !expired_keys.is_empty();
    for key in expired_keys {
        store.remove(&key);
    }

    Ok(had_expired_keys)
}

fn keyring_error(error: KeyringError) -> String {
    format!("keychain operation failed: {error}")
}

fn is_pkce_record_expired(created_at_ms: u128) -> Result<bool, String> {
    let now = now_millis()?;
    Ok(created_at_ms > now || now - created_at_ms > PKCE_VERIFIER_MAX_AGE_MS)
}

fn now_millis() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| format!("system clock is before UNIX_EPOCH: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_secret_keys_allow_only_expected_user_scoped_domains() {
        assert_eq!(
            normalize_local_secret_key("device-key:00000000-0000-4000-8000-000000000001").unwrap(),
            "device-key:00000000-0000-4000-8000-000000000001",
        );
        assert_eq!(
            normalize_local_secret_key(" vault-integrity:00000000-0000-4000-8000-000000000001 ").unwrap(),
            "vault-integrity:00000000-0000-4000-8000-000000000001",
        );
    }

    #[test]
    fn local_secret_keys_reject_free_form_accounts() {
        for key in [
            "",
            "device-key:test",
            "refresh-token:00000000-0000-4000-8000-000000000001",
            "vault-integrity:user-1",
            "device-key:00000000-0000-4000-8000-000000000001:extra",
            "device-key:00000000-0000-1000-8000-000000000001",
            "device-key:00000000-0000-4000-7000-000000000001",
        ] {
            assert!(normalize_local_secret_key(key).is_err(), "{key} should be rejected");
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let context = tauri::generate_context!();
    purge_stale_webview_service_worker_data(context.config().identifier.as_str());

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let deep_link_urls = extract_deep_link_urls(&args);
            if !deep_link_urls.is_empty() {
                let _ = app.emit(SINGLE_INSTANCE_DEEP_LINK_EVENT, deep_link_urls);
            }

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            save_refresh_token,
            load_refresh_token,
            clear_refresh_token,
            save_pkce_verifier,
            load_pkce_verifier,
            clear_pkce_verifier,
            save_local_secret,
            load_local_secret,
            clear_local_secret
        ])
        .setup(|_app| {
            #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                _app.deep_link().register_all()?;
            }

            Ok(())
        })
        .run(context)
        .expect("error while running Singra Vault");
}

fn extract_deep_link_urls(args: &[String]) -> Vec<String> {
    args.iter()
        .filter_map(|arg| {
            let candidate = arg.trim();
            if candidate.starts_with(TAURI_OAUTH_CALLBACK_PREFIX) {
                Some(candidate.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn purge_stale_webview_service_worker_data(app_identifier: &str) {
    #[cfg(target_os = "windows")]
    {
        if let Some(default_profile_dir) = resolve_windows_webview_default_profile_dir(app_identifier) {
            remove_dir_if_exists(default_profile_dir.join("Service Worker"));
            remove_dir_if_exists(default_profile_dir.join("Cache").join("Cache_Data"));
        }
    }
}

fn remove_dir_if_exists(path: PathBuf) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

#[cfg(target_os = "windows")]
fn resolve_windows_webview_default_profile_dir(app_identifier: &str) -> Option<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")?;
    Some(
        PathBuf::from(local_app_data)
            .join(app_identifier)
            .join("EBWebView")
            .join("Default"),
    )
}
