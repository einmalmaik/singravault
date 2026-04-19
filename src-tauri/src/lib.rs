use keyring::{Entry, Error as KeyringError};
use tauri::Manager;

const KEYCHAIN_SERVICE: &str = "Singra Vault";
const REFRESH_TOKEN_ACCOUNT: &str = "active-refresh-token";

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

fn keychain_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, REFRESH_TOKEN_ACCOUNT).map_err(keyring_error)
}

fn keyring_error(error: KeyringError) -> String {
    format!("keychain operation failed: {error}")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .invoke_handler(tauri::generate_handler![
            save_refresh_token,
            load_refresh_token,
            clear_refresh_token
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
