use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Duration;
use tauri::{Emitter, Manager};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::LocalFree;

const KEYCHAIN_SERVICE: &str = "Singra Vault";
const REFRESH_TOKEN_ACCOUNT: &str = "active-refresh-token";
const PKCE_VERIFIER_ACCOUNT: &str = "active-pkce-verifier";
const LOCAL_SECRET_ACCOUNT_PREFIX: &str = "local-secret::";
const DEVICE_KEY_LOCAL_SECRET_PREFIX: &str = "device-key:";
const INTEGRITY_LOCAL_SECRET_PREFIX: &str = "vault-integrity:";
const DEVICE_KEY_LENGTH: usize = 32;
const ARGON2_OUTPUT_LENGTH: usize = 32;
const DERIVED_KEY_LENGTH: usize = 32;
const DEVICE_KEY_DERIVATION_VERSION: u8 = 1;
const DEVICE_KEY_HKDF_INFO: &[u8] = b"SINGRA_DEVICE_KEY_V1";
const DEVICE_KEY_TRANSFER_V2_PREFIX: &str = "sv-dk-transfer-v2:";
const DEVICE_KEY_TRANSFER_MAX_ENVELOPE_LENGTH: usize = 16_384;
const DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH: usize = 20;
const TRANSFER_SALT_LENGTH: usize = 16;
const TRANSFER_IV_LENGTH: usize = 12;
const TRANSFER_KDF_MEMORY_KIB: u32 = 65_536;
const TRANSFER_KDF_ITERATIONS: u32 = 3;
const TRANSFER_KDF_PARALLELISM: u32 = 1;
const TRANSFER_KDF_HASH_LENGTH: usize = 32;
const PKCE_VERIFIER_MAX_AGE_MS: u128 = 10 * 60 * 1000;
const SINGLE_INSTANCE_DEEP_LINK_EVENT: &str = "singra://deep-link";
const TAURI_OAUTH_CALLBACK_PREFIX: &str = "singravault://auth/callback";
const DEVICE_KEY_READBACK_ATTEMPTS: usize = 20;
const DEVICE_KEY_READBACK_DELAY_MS: u64 = 100;
const DEVICE_KEY_FALLBACK_DIR: &str = "device-keys";

const DEVICE_KEY_MISSING: &str = "DEVICE_KEY_MISSING";
const DEVICE_KEY_ALREADY_EXISTS: &str = "DEVICE_KEY_ALREADY_EXISTS";
const DEVICE_KEY_INVALID_USER_ID: &str = "DEVICE_KEY_INVALID_USER_ID";
const DEVICE_KEY_INVALID_INPUT: &str = "DEVICE_KEY_INVALID_INPUT";
const DEVICE_KEY_STORE_UNAVAILABLE: &str = "DEVICE_KEY_STORE_UNAVAILABLE";
const DEVICE_KEY_CRYPTO_FAILED: &str = "DEVICE_KEY_CRYPTO_FAILED";

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

#[derive(Serialize, Deserialize)]
struct DeviceKeyTransferEnvelopeV2 {
    version: u8,
    kdf: String,
    memory: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
    iv: String,
    ciphertext: String,
    #[serde(rename = "createdAt")]
    created_at: String,
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

    let mut store = load_pkce_store()?;
    store.insert(
        key.to_string(),
        PkceVerifierStoreEntry {
            verifier: verifier.to_string(),
            created_at_ms: now_millis()?,
        },
    );
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
    let entry = local_secret_entry_for_write(&key)?;
    let trimmed_value = value.trim();
    if trimmed_value.is_empty() {
        return Err("local secret value must not be empty".to_string());
    }

    entry.set_password(trimmed_value).map_err(keyring_error)
}

#[tauri::command]
fn load_local_secret(key: String) -> Result<Option<String>, String> {
    let entry = local_secret_entry_for_read(&key)?;
    match entry.get_password() {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

#[tauri::command]
fn clear_local_secret(key: String) -> Result<(), String> {
    let entry = local_secret_entry_for_clear(&key)?;
    match entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => Err(keyring_error(error)),
    }
}

#[tauri::command]
fn verify_device_key_available(user_id: String) -> Result<bool, String> {
    match load_device_key_bytes(&user_id) {
        Ok(Some(mut device_key)) => {
            device_key.fill(0);
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(error) => Err(error),
    }
}

#[tauri::command]
fn generate_and_store_device_key(user_id: String) -> Result<(), String> {
    let entry = device_key_entry_for_user(&user_id)?;
    if load_device_key_bytes(&user_id)?.is_some() {
        return Err(DEVICE_KEY_ALREADY_EXISTS.to_string());
    }

    let mut device_key = [0u8; DEVICE_KEY_LENGTH];
    getrandom::getrandom(&mut device_key).map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    store_device_key_for_user(&user_id, &entry, &device_key)?;
    device_key.fill(0);
    Ok(())
}

#[tauri::command]
fn delete_native_device_key(user_id: String) -> Result<(), String> {
    clear_device_key_storage(&user_id)
}

#[tauri::command]
fn derive_device_protected_key(
    user_id: String,
    argon2_output_base64: String,
    version: u8,
) -> Result<String, String> {
    if version != DEVICE_KEY_DERIVATION_VERSION {
        return Err(DEVICE_KEY_INVALID_INPUT.to_string());
    }

    let mut argon2_output = decode_fixed_base64(&argon2_output_base64, ARGON2_OUTPUT_LENGTH)?;
    let mut device_key = match load_device_key_bytes(&user_id)? {
        Some(device_key) => device_key,
        None => {
            argon2_output.fill(0);
            return Err(DEVICE_KEY_MISSING.to_string());
        }
    };

    let derived = derive_device_protected_key_bytes(&argon2_output, &device_key)?;
    argon2_output.fill(0);
    device_key.fill(0);
    Ok(BASE64.encode(derived))
}

#[tauri::command]
fn export_device_key_for_transfer(
    user_id: String,
    transfer_secret: String,
) -> Result<Option<String>, String> {
    if !is_valid_transfer_secret(&transfer_secret) {
        return Ok(None);
    }

    let mut device_key = match load_device_key_bytes(&user_id)? {
        Some(device_key) => device_key,
        None => return Ok(None),
    };
    let mut salt = [0u8; TRANSFER_SALT_LENGTH];
    let mut iv = [0u8; TRANSFER_IV_LENGTH];
    getrandom::getrandom(&mut salt).map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    getrandom::getrandom(&mut iv).map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;

    let mut wrapping_key = derive_transfer_wrapping_key(transfer_secret.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&iv), device_key.as_slice())
        .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;

    let envelope = DeviceKeyTransferEnvelopeV2 {
        version: 2,
        kdf: "argon2id".to_string(),
        memory: TRANSFER_KDF_MEMORY_KIB,
        iterations: TRANSFER_KDF_ITERATIONS,
        parallelism: TRANSFER_KDF_PARALLELISM,
        salt: BASE64.encode(salt),
        iv: BASE64.encode(iv),
        ciphertext: BASE64.encode(ciphertext),
        created_at: now_millis()?.to_string(),
    };
    let payload =
        serde_json::to_vec(&envelope).map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    let transfer = format!("{DEVICE_KEY_TRANSFER_V2_PREFIX}{}", BASE64.encode(payload));

    device_key.fill(0);
    wrapping_key.fill(0);
    salt.fill(0);
    iv.fill(0);

    Ok(Some(transfer))
}

#[tauri::command]
fn import_device_key_from_transfer(
    user_id: String,
    transfer_data: String,
    transfer_secret: String,
) -> Result<bool, String> {
    if !is_valid_transfer_secret(&transfer_secret)
        || !transfer_data.starts_with(DEVICE_KEY_TRANSFER_V2_PREFIX)
        || transfer_data.len() > DEVICE_KEY_TRANSFER_MAX_ENVELOPE_LENGTH
    {
        return Ok(false);
    }

    let entry = device_key_entry_for_user(&user_id)?;
    if load_device_key_bytes(&user_id)?.is_some() {
        return Ok(false);
    }

    let envelope = parse_transfer_envelope(&transfer_data)?;
    if !is_supported_transfer_envelope(&envelope) {
        return Ok(false);
    }

    let salt = decode_fixed_base64(&envelope.salt, TRANSFER_SALT_LENGTH)?;
    let iv = decode_fixed_base64(&envelope.iv, TRANSFER_IV_LENGTH)?;
    let ciphertext = BASE64
        .decode(envelope.ciphertext.trim())
        .map_err(|_| DEVICE_KEY_INVALID_INPUT.to_string())?;
    if ciphertext.is_empty() {
        return Ok(false);
    }

    let mut wrapping_key = derive_transfer_wrapping_key(transfer_secret.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    let mut device_key = match cipher.decrypt(Nonce::from_slice(&iv), ciphertext.as_slice()) {
        Ok(device_key) => device_key,
        Err(_) => {
            wrapping_key.fill(0);
            return Ok(false);
        }
    };

    if device_key.len() != DEVICE_KEY_LENGTH {
        device_key.fill(0);
        wrapping_key.fill(0);
        return Ok(false);
    }

    store_device_key_for_user(&user_id, &entry, &device_key)?;
    device_key.fill(0);
    wrapping_key.fill(0);
    Ok(true)
}

fn keychain_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, REFRESH_TOKEN_ACCOUNT).map_err(keyring_error)
}

fn pkce_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, PKCE_VERIFIER_ACCOUNT).map_err(keyring_error)
}

fn local_secret_entry_for_write(key: &str) -> Result<Entry, String> {
    let normalized_key = normalize_local_secret_key_for_write(key)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{normalized_key}");
    Entry::new(KEYCHAIN_SERVICE, &account).map_err(keyring_error)
}

fn local_secret_entry_for_read(key: &str) -> Result<Entry, String> {
    let normalized_key = normalize_local_secret_key_for_read(key)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{normalized_key}");
    Entry::new(KEYCHAIN_SERVICE, &account).map_err(keyring_error)
}

fn local_secret_entry_for_clear(key: &str) -> Result<Entry, String> {
    let normalized_key = normalize_local_secret_key_for_clear(key)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{normalized_key}");
    Entry::new(KEYCHAIN_SERVICE, &account).map_err(keyring_error)
}

fn normalize_local_secret_key_for_write(key: &str) -> Result<String, String> {
    normalize_local_secret_key(key, false)
}

fn normalize_local_secret_key_for_read(key: &str) -> Result<String, String> {
    normalize_local_secret_key(key, false)
}

fn normalize_local_secret_key_for_clear(key: &str) -> Result<String, String> {
    normalize_local_secret_key(key, true)
}

fn normalize_local_secret_key(key: &str, allow_device_key: bool) -> Result<String, String> {
    let normalized_key = key.trim();

    if allow_device_key
        && is_allowed_user_scoped_secret_key(normalized_key, DEVICE_KEY_LOCAL_SECRET_PREFIX)
    {
        return Ok(normalized_key.to_string());
    }

    if is_allowed_user_scoped_secret_key(normalized_key, INTEGRITY_LOCAL_SECRET_PREFIX) {
        return Ok(normalized_key.to_string());
    }

    Err("local secret key is not allowed".to_string())
}

fn device_key_entry_for_user(user_id: &str) -> Result<Entry, String> {
    let user_id = validate_user_id(user_id)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{DEVICE_KEY_LOCAL_SECRET_PREFIX}{user_id}");
    Entry::new_with_target(&account, KEYCHAIN_SERVICE, DEVICE_KEY_LOCAL_SECRET_PREFIX)
        .map_err(keyring_error)
}

fn legacy_device_key_entry_for_user(user_id: &str) -> Result<Entry, String> {
    let user_id = validate_user_id(user_id)?;
    let account = format!("{LOCAL_SECRET_ACCOUNT_PREFIX}{DEVICE_KEY_LOCAL_SECRET_PREFIX}{user_id}");
    Entry::new(KEYCHAIN_SERVICE, &account).map_err(keyring_error)
}

fn validate_user_id(user_id: &str) -> Result<&str, String> {
    let trimmed = user_id.trim();
    if is_uuid_like(trimmed) {
        Ok(trimmed)
    } else {
        Err(DEVICE_KEY_INVALID_USER_ID.to_string())
    }
}

fn load_device_key_bytes(user_id: &str) -> Result<Option<Vec<u8>>, String> {
    let entry = device_key_entry_for_user(user_id)?;
    match load_device_key_secret(&entry) {
        Ok(Some(device_key)) => Ok(Some(device_key)),
        Err(error) if error == DEVICE_KEY_STORE_UNAVAILABLE => load_device_key_fallback(user_id),
        Ok(None) => {
            let legacy_entry = legacy_device_key_entry_for_user(user_id)?;
            match load_device_key_secret(&legacy_entry) {
                Ok(Some(device_key)) => {
                    store_device_key_for_user(user_id, &entry, &device_key)?;
                    let _ = legacy_entry.delete_credential();
                    Ok(Some(device_key))
                }
                Err(error) if error == DEVICE_KEY_STORE_UNAVAILABLE => load_device_key_fallback(user_id),
                Ok(None) => load_device_key_fallback(user_id),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn store_device_key_for_user(user_id: &str, entry: &Entry, device_key: &[u8]) -> Result<(), String> {
    match store_device_key_secret(entry, device_key) {
        Ok(()) => match verify_device_key_readback(user_id) {
            Ok(()) => Ok(()),
            Err(error) if error == DEVICE_KEY_STORE_UNAVAILABLE => store_device_key_fallback(user_id, device_key),
            Err(error) => Err(error),
        },
        Err(error) if error == DEVICE_KEY_STORE_UNAVAILABLE => store_device_key_fallback(user_id, device_key),
        Err(error) => Err(error),
    }
}

fn store_device_key_secret(entry: &Entry, device_key: &[u8]) -> Result<(), String> {
    entry
        .set_secret(device_key)
        .map_err(map_keyring_error_code)
}

fn load_device_key_secret(entry: &Entry) -> Result<Option<Vec<u8>>, String> {
    match entry.get_secret() {
        Ok(secret) if secret.is_empty() => Ok(None),
        Ok(secret) => {
            if secret.len() != DEVICE_KEY_LENGTH {
                return Err(DEVICE_KEY_INVALID_INPUT.to_string());
            }
            Ok(Some(secret))
        }
        Err(KeyringError::NoEntry) => load_legacy_password_device_key(entry),
        Err(error) => Err(map_keyring_error_code(error)),
    }
}

fn load_legacy_password_device_key(entry: &Entry) -> Result<Option<Vec<u8>>, String> {
    let payload = match entry.get_password() {
        Ok(value) if value.trim().is_empty() => return Ok(None),
        Ok(value) => value,
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(error) => return Err(map_keyring_error_code(error)),
    };

    let device_key = decode_fixed_base64(&payload, DEVICE_KEY_LENGTH)?;
    entry
        .set_secret(&device_key)
        .map_err(map_keyring_error_code)?;
    Ok(Some(device_key))
}

fn verify_device_key_readback(user_id: &str) -> Result<(), String> {
    for attempt in 0..DEVICE_KEY_READBACK_ATTEMPTS {
        match load_device_key_bytes(user_id) {
            Ok(Some(mut device_key)) => {
                device_key.fill(0);
                return Ok(());
            }
            Ok(None) if attempt + 1 < DEVICE_KEY_READBACK_ATTEMPTS => {
                sleep(Duration::from_millis(DEVICE_KEY_READBACK_DELAY_MS));
            }
            Ok(None) => return Err(DEVICE_KEY_STORE_UNAVAILABLE.to_string()),
            Err(error) => return Err(error),
        }
    }

    Err(DEVICE_KEY_STORE_UNAVAILABLE.to_string())
}

fn clear_device_key_storage(user_id: &str) -> Result<(), String> {
    let primary_entry = device_key_entry_for_user(user_id)?;
    match primary_entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => {}
        Err(error) => return Err(map_keyring_error_code(error)),
    }

    let legacy_entry = legacy_device_key_entry_for_user(user_id)?;
    match legacy_entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => clear_device_key_fallback(user_id),
        Err(error) => Err(map_keyring_error_code(error)),
    }
}

#[cfg(target_os = "windows")]
fn store_device_key_fallback(user_id: &str, device_key: &[u8]) -> Result<(), String> {
    let protected = protect_device_key_bytes(device_key)?;
    let path = device_key_fallback_path(user_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| DEVICE_KEY_STORE_UNAVAILABLE.to_string())?;
    }
    fs::write(path, protected).map_err(|_| DEVICE_KEY_STORE_UNAVAILABLE.to_string())
}

#[cfg(not(target_os = "windows"))]
fn store_device_key_fallback(_user_id: &str, _device_key: &[u8]) -> Result<(), String> {
    Err(DEVICE_KEY_STORE_UNAVAILABLE.to_string())
}

#[cfg(target_os = "windows")]
fn load_device_key_fallback(user_id: &str) -> Result<Option<Vec<u8>>, String> {
    let path = device_key_fallback_path(user_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let payload = fs::read(path).map_err(|_| DEVICE_KEY_STORE_UNAVAILABLE.to_string())?;
    unprotect_device_key_bytes(&payload).map(Some)
}

#[cfg(not(target_os = "windows"))]
fn load_device_key_fallback(_user_id: &str) -> Result<Option<Vec<u8>>, String> {
    Ok(None)
}

#[cfg(target_os = "windows")]
fn clear_device_key_fallback(user_id: &str) -> Result<(), String> {
    let path = device_key_fallback_path(user_id)?;
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path).map_err(|_| DEVICE_KEY_STORE_UNAVAILABLE.to_string())
}

#[cfg(not(target_os = "windows"))]
fn clear_device_key_fallback(_user_id: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn device_key_fallback_path(user_id: &str) -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| DEVICE_KEY_STORE_UNAVAILABLE.to_string())?;
    Ok(base.join("Singra Vault").join(DEVICE_KEY_FALLBACK_DIR).join(format!("{user_id}.bin")))
}

#[cfg(target_os = "windows")]
fn protect_device_key_bytes(device_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: device_key.len() as u32,
        pbData: device_key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let success = unsafe {
        CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 0 {
        return Err(DEVICE_KEY_STORE_UNAVAILABLE.to_string());
    }

    let protected = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(protected)
}

#[cfg(target_os = "windows")]
fn unprotect_device_key_bytes(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: payload.len() as u32,
        pbData: payload.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let success = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 0 {
        return Err(DEVICE_KEY_STORE_UNAVAILABLE.to_string());
    }

    let device_key = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(output.pbData as _);
    }
    if device_key.len() != DEVICE_KEY_LENGTH {
        return Err(DEVICE_KEY_INVALID_INPUT.to_string());
    }
    Ok(device_key)
}

fn decode_fixed_base64(value: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let decoded = BASE64
        .decode(value.trim())
        .map_err(|_| DEVICE_KEY_INVALID_INPUT.to_string())?;
    if decoded.len() != expected_len {
        return Err(DEVICE_KEY_INVALID_INPUT.to_string());
    }
    Ok(decoded)
}

fn derive_device_protected_key_bytes(
    argon2_output: &[u8],
    device_key: &[u8],
) -> Result<[u8; DERIVED_KEY_LENGTH], String> {
    if argon2_output.len() != ARGON2_OUTPUT_LENGTH || device_key.len() != DEVICE_KEY_LENGTH {
        return Err(DEVICE_KEY_INVALID_INPUT.to_string());
    }

    let hk = Hkdf::<Sha256>::new(Some(device_key), argon2_output);
    let mut output = [0u8; DERIVED_KEY_LENGTH];
    hk.expand(DEVICE_KEY_HKDF_INFO, &mut output)
        .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    Ok(output)
}

fn is_valid_transfer_secret(transfer_secret: &str) -> bool {
    transfer_secret.len() >= DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH
}

fn derive_transfer_wrapping_key(
    transfer_secret: &[u8],
    salt: &[u8],
) -> Result<[u8; TRANSFER_KDF_HASH_LENGTH], String> {
    if salt.len() != TRANSFER_SALT_LENGTH {
        return Err(DEVICE_KEY_INVALID_INPUT.to_string());
    }

    let params = Params::new(
        TRANSFER_KDF_MEMORY_KIB,
        TRANSFER_KDF_ITERATIONS,
        TRANSFER_KDF_PARALLELISM,
        Some(TRANSFER_KDF_HASH_LENGTH),
    )
    .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; TRANSFER_KDF_HASH_LENGTH];
    argon2
        .hash_password_into(transfer_secret, salt, &mut output)
        .map_err(|_| DEVICE_KEY_CRYPTO_FAILED.to_string())?;
    Ok(output)
}

fn parse_transfer_envelope(transfer_data: &str) -> Result<DeviceKeyTransferEnvelopeV2, String> {
    let payload = transfer_data
        .trim()
        .strip_prefix(DEVICE_KEY_TRANSFER_V2_PREFIX)
        .ok_or_else(|| DEVICE_KEY_INVALID_INPUT.to_string())?;
    let json = BASE64
        .decode(payload)
        .map_err(|_| DEVICE_KEY_INVALID_INPUT.to_string())?;
    serde_json::from_slice(&json).map_err(|_| DEVICE_KEY_INVALID_INPUT.to_string())
}

fn is_supported_transfer_envelope(envelope: &DeviceKeyTransferEnvelopeV2) -> bool {
    envelope.version == 2
        && envelope.kdf == "argon2id"
        && envelope.memory == TRANSFER_KDF_MEMORY_KIB
        && envelope.iterations == TRANSFER_KDF_ITERATIONS
        && envelope.parallelism == TRANSFER_KDF_PARALLELISM
}

fn is_allowed_user_scoped_secret_key(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix).map(is_uuid_like).unwrap_or(false)
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
        && matches!(
            value.as_bytes()[19],
            b'8' | b'9' | b'a' | b'b' | b'A' | b'B'
        )
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
                store.insert(
                    record.key,
                    PkceVerifierStoreEntry {
                        verifier: record.verifier,
                        created_at_ms: record.created_at_ms,
                    },
                );
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

fn map_keyring_error_code(error: KeyringError) -> String {
    match error {
        KeyringError::NoEntry => DEVICE_KEY_MISSING.to_string(),
        _ => DEVICE_KEY_STORE_UNAVAILABLE.to_string(),
    }
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static DEVICE_KEY_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn next_test_user_id() -> String {
        let suffix = DEVICE_KEY_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("00000000-0000-4000-8000-{:012x}", suffix)
    }

    fn clear_test_device_key(user_id: &str) {
        let _ = clear_device_key_storage(user_id);
    }

    #[test]
    fn local_secret_keys_allow_only_expected_user_scoped_domains() {
        assert_eq!(
            normalize_local_secret_key_for_clear("device-key:00000000-0000-4000-8000-000000000001")
                .unwrap(),
            "device-key:00000000-0000-4000-8000-000000000001",
        );
        assert_eq!(
            normalize_local_secret_key_for_read(
                " vault-integrity:00000000-0000-4000-8000-000000000001 "
            )
            .unwrap(),
            "vault-integrity:00000000-0000-4000-8000-000000000001",
        );
    }

    #[test]
    fn local_secret_read_write_blocks_device_key_namespace() {
        assert!(normalize_local_secret_key_for_read(
            "device-key:00000000-0000-4000-8000-000000000001"
        )
        .is_err());
        assert!(normalize_local_secret_key_for_write(
            "device-key:00000000-0000-4000-8000-000000000001"
        )
        .is_err());
        assert!(normalize_local_secret_key_for_clear(
            "device-key:00000000-0000-4000-8000-000000000001"
        )
        .is_ok());
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
            assert!(
                normalize_local_secret_key_for_write(key).is_err(),
                "{key} should be rejected"
            );
        }
    }

    #[test]
    fn device_key_derivation_matches_js_hkdf_vector() {
        let argon2_output: Vec<u8> = (0u8..32).collect();
        let device_key: Vec<u8> = (0u8..32).map(|value| 255 - value).collect();

        let derived = derive_device_protected_key_bytes(&argon2_output, &device_key).unwrap();

        assert_eq!(
            BASE64.encode(derived),
            "VW/q6Mi+eLJhEtBaRtt9/aYVr4IuZR8cndy7hqtX/dg="
        );
    }

    #[test]
    fn device_key_derivation_rejects_wrong_lengths() {
        assert!(derive_device_protected_key_bytes(&[1u8; 31], &[2u8; 32]).is_err());
        assert!(derive_device_protected_key_bytes(&[1u8; 32], &[2u8; 31]).is_err());
    }

    #[test]
    fn device_key_user_id_requires_uuid_v4() {
        assert_eq!(
            validate_user_id("00000000-0000-4000-8000-000000000001").unwrap(),
            "00000000-0000-4000-8000-000000000001",
        );
        assert_eq!(
            validate_user_id("00000000-0000-1000-8000-000000000001").unwrap_err(),
            DEVICE_KEY_INVALID_USER_ID,
        );
    }

    #[test]
    #[ignore = "requires OS keychain access"]
    fn native_device_key_roundtrip_through_os_keychain() {
        let user_id = next_test_user_id();
        clear_test_device_key(&user_id);

        generate_and_store_device_key(user_id.clone()).unwrap();
        assert_eq!(verify_device_key_available(user_id.clone()).unwrap(), true);

        let argon2_output = BASE64.encode([7u8; ARGON2_OUTPUT_LENGTH]);
        let first = derive_device_protected_key(user_id.clone(), argon2_output.clone(), 1).unwrap();
        let second = derive_device_protected_key(user_id.clone(), argon2_output, 1).unwrap();
        assert_eq!(first, second);

        clear_test_device_key(&user_id);
    }

    #[test]
    #[ignore = "requires OS keychain access"]
    fn native_device_key_transfer_export_import_roundtrip() {
        let source_user_id = next_test_user_id();
        let target_user_id = next_test_user_id();
        let transfer_secret = "device-key-transfer-secret-123";

        clear_test_device_key(&source_user_id);
        clear_test_device_key(&target_user_id);

        generate_and_store_device_key(source_user_id.clone()).unwrap();
        let export = export_device_key_for_transfer(
            source_user_id.clone(),
            transfer_secret.to_string(),
        )
        .unwrap()
        .unwrap();

        let imported = import_device_key_from_transfer(
            target_user_id.clone(),
            export,
            transfer_secret.to_string(),
        )
        .unwrap();
        assert_eq!(imported, true);
        assert_eq!(verify_device_key_available(target_user_id.clone()).unwrap(), true);

        clear_test_device_key(&source_user_id);
        clear_test_device_key(&target_user_id);
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
            clear_local_secret,
            verify_device_key_available,
            delete_native_device_key,
            generate_and_store_device_key,
            derive_device_protected_key,
            export_device_key_for_transfer,
            import_device_key_from_transfer
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
        if let Some(default_profile_dir) =
            resolve_windows_webview_default_profile_dir(app_identifier)
        {
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
