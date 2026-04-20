use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Manager;

const KEYCHAIN_SERVICE: &str = "Singra Vault";
const REFRESH_TOKEN_ACCOUNT: &str = "active-refresh-token";
const PKCE_VERIFIER_ACCOUNT: &str = "active-pkce-verifier";
const PKCE_VERIFIER_MAX_AGE_MS: u128 = 10 * 60 * 1000;

#[derive(Serialize, Deserialize)]
struct PkceVerifierRecord {
    key: String,
    verifier: String,
    created_at_ms: u128,
}

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

    let record = PkceVerifierRecord {
        key: key.to_string(),
        verifier: verifier.to_string(),
        created_at_ms: now_millis()?,
    };
    let payload = serde_json::to_string(&record)
        .map_err(|error| format!("PKCE verifier serialization failed: {error}"))?;

    pkce_entry()?.set_password(&payload).map_err(keyring_error)
}

#[tauri::command]
fn load_pkce_verifier(key: String) -> Result<Option<String>, String> {
    let requested_key = key.trim();
    if requested_key.is_empty() {
        return Ok(None);
    }

    let payload = match pkce_entry()?.get_password() {
        Ok(payload) if payload.trim().is_empty() => return Ok(None),
        Ok(payload) => payload,
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(error) => return Err(keyring_error(error)),
    };

    let record = match serde_json::from_str::<PkceVerifierRecord>(&payload) {
        Ok(record) => record,
        Err(_) => {
            clear_pkce_verifier(requested_key.to_string())?;
            return Ok(None);
        }
    };

    if is_pkce_record_expired(record.created_at_ms)? {
        clear_pkce_verifier(requested_key.to_string())?;
        return Ok(None);
    }

    if record.key == requested_key && !record.verifier.trim().is_empty() {
        Ok(Some(record.verifier))
    } else {
        Ok(None)
    }
}

#[tauri::command]
fn clear_pkce_verifier(_key: String) -> Result<(), String> {
    match pkce_entry()?.delete_credential() {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
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
            clear_pkce_verifier
        ])
        .setup(|_app| {
            #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                _app.deep_link().register_all()?;
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Singra Vault");
}
