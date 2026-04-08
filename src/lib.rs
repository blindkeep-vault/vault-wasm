use vault_core::bindings;
use vault_core::bindings::client_ops;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_js<T>(r: Result<T, String>) -> Result<T, JsError> {
    r.map_err(|e| JsError::new(&e))
}

fn to_js_val(r: Result<JsValue, String>) -> Result<JsValue, JsError> {
    r.map_err(|e| JsError::new(&e))
}

fn json_to_js(val: &impl serde::Serialize) -> Result<JsValue, String> {
    serde_wasm_bindgen::to_value(val).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::derive_key_impl(password, salt))
}

#[wasm_bindgen]
pub fn derive_key_legacy(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::derive_key_legacy_impl(password, salt))
}

#[wasm_bindgen]
pub fn derive_subkey(master_key: &[u8], info: &str) -> Result<Vec<u8>, JsError> {
    to_js(bindings::derive_subkey_impl(master_key, info))
}

#[wasm_bindgen]
pub fn derive_subkey_salted(
    master_key: &[u8],
    salt: &[u8],
    info: &str,
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::derive_subkey_salted_impl(master_key, salt, info))
}

/// Derive API key wrapping_key and auth_key from a 32-byte secret.
/// Returns {wrapping_key: Vec<u8>, auth_key: Vec<u8>}.
#[wasm_bindgen]
pub fn derive_api_key_keys(secret: &[u8]) -> Result<JsValue, JsError> {
    let (wk, ak) = to_js(bindings::derive_api_key_keys_impl(secret))?;
    to_js_val(json_to_js(&serde_json::json!({
        "wrapping_key": wk,
        "auth_key": ak,
    })))
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsError> {
    let (private_key, public_key) = bindings::generate_keypair_impl();
    to_js_val(json_to_js(&serde_json::json!({
        "private_key": private_key,
        "public_key": public_key,
    })))
}

#[wasm_bindgen]
pub fn generate_random_key() -> Vec<u8> {
    bindings::generate_random_key_impl()
}

// ---------------------------------------------------------------------------
// Symmetric encryption
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<JsValue, JsError> {
    let (ciphertext, nonce) = to_js(bindings::encrypt_impl(key, plaintext))?;
    to_js_val(json_to_js(&serde_json::json!({
        "ciphertext": ciphertext,
        "nonce": nonce,
    })))
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::decrypt_impl(key, ciphertext, nonce))
}

#[wasm_bindgen]
pub fn encrypt_v1(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<JsValue, JsError> {
    let (ciphertext, nonce) = to_js(bindings::encrypt_v1_impl(key, plaintext, aad))?;
    to_js_val(json_to_js(&serde_json::json!({
        "ciphertext": ciphertext,
        "nonce": nonce,
    })))
}

#[wasm_bindgen]
pub fn decrypt_auto(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::decrypt_auto_impl(key, ciphertext, nonce, aad))
}

// ---------------------------------------------------------------------------
// Asymmetric key wrapping (V0)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wrap_key_for_recipient(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<JsValue, JsError> {
    let (wrapped_key, ephemeral_pubkey, nonce) = to_js(bindings::wrap_key_for_recipient_impl(
        item_key,
        recipient_pubkey,
    ))?;
    to_js_val(json_to_js(&serde_json::json!({
        "wrapped_key": wrapped_key,
        "ephemeral_pubkey": ephemeral_pubkey,
        "nonce": nonce,
    })))
}

#[wasm_bindgen]
pub fn unwrap_key(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::unwrap_key_impl(
        privkey,
        ephemeral_pub,
        wrapped,
        nonce,
    ))
}

// ---------------------------------------------------------------------------
// Asymmetric key wrapping (V1)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wrap_key_for_recipient_v1(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<JsValue, JsError> {
    let (wrapped_key, ephemeral_pubkey, nonce) = to_js(bindings::wrap_key_for_recipient_v1_impl(
        item_key,
        recipient_pubkey,
    ))?;
    to_js_val(json_to_js(&serde_json::json!({
        "wrapped_key": wrapped_key,
        "ephemeral_pubkey": ephemeral_pubkey,
        "nonce": nonce,
    })))
}

#[wasm_bindgen]
pub fn unwrap_key_v1(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::unwrap_key_v1_impl(
        privkey,
        ephemeral_pub,
        wrapped,
        nonce,
        recipient_pubkey,
    ))
}

// ---------------------------------------------------------------------------
// Grant key wrapping
// ---------------------------------------------------------------------------

/// Wrap an item key for a grant recipient (V1 key-bound).
/// Returns {grant_wrapped_key: nonce||ciphertext, ephemeral_pubkey: 32 bytes}.
#[wasm_bindgen]
pub fn wrap_key_for_grant(item_key: &[u8], recipient_pubkey: &[u8]) -> Result<JsValue, JsError> {
    let (gwk, ep) = to_js(bindings::wrap_key_for_grant_impl(
        item_key,
        recipient_pubkey,
    ))?;
    to_js_val(json_to_js(&serde_json::json!({
        "grant_wrapped_key": gwk,
        "ephemeral_pubkey": ep,
    })))
}

/// Unwrap a grant-format wrapped key (nonce||ciphertext). Auto-detects V0/V1.
#[wasm_bindgen]
pub fn unwrap_grant_key(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    grant_wrapped_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::unwrap_grant_key_impl(
        privkey,
        ephemeral_pub,
        grant_wrapped_key,
        recipient_pubkey,
    ))
}

// ---------------------------------------------------------------------------
// Symmetric key wrapping / private key decryption
// ---------------------------------------------------------------------------

/// Wrap a 32-byte key (e.g. API key private key) with a wrapping key.
/// Returns nonce(24) || ciphertext as a single byte array.
#[wasm_bindgen]
pub fn wrap_key_symmetric(wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::wrap_key_symmetric_impl(wrapping_key, key_to_wrap))
}

/// Decrypt a user's private key from stored format (nonce(24) || ciphertext).
#[wasm_bindgen]
pub fn decrypt_private_key(
    enc_key: &[u8],
    encrypted_private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(bindings::decrypt_private_key_impl(
        enc_key,
        encrypted_private_key,
    ))
}

// ---------------------------------------------------------------------------
// Claim secret
// ---------------------------------------------------------------------------

/// Encrypt a 32-byte link secret with a claim key using AES-256-GCM.
/// Returns iv(12) || ciphertext. Compatible with SubtleCrypto AES-GCM.
#[wasm_bindgen]
pub fn encrypt_claim_secret(claim_key: &[u8], link_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::encrypt_claim_secret_impl(claim_key, link_secret))
}

/// Decrypt a 32-byte link secret from iv(12) || ciphertext using AES-256-GCM.
#[wasm_bindgen]
pub fn decrypt_claim_secret(claim_key: &[u8], claim_ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::decrypt_claim_secret_impl(
        claim_key,
        claim_ciphertext,
    ))
}

// ---------------------------------------------------------------------------
// Notarization
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn verify_notarization(
    pubkey: &[u8],
    content_hash: &[u8],
    blob_hash: &[u8],
    timestamp_millis: i64,
    tree_root: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    let bh = if blob_hash.is_empty() {
        None
    } else {
        Some(blob_hash)
    };
    to_js(bindings::verify_notarization_impl(
        pubkey,
        content_hash,
        bh,
        timestamp_millis,
        tree_root,
        signature,
    ))
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn check_policy(policy_json: &str, view_count: i32, operation: &str) -> Result<bool, JsError> {
    to_js(bindings::check_policy_impl(
        policy_json,
        view_count,
        operation,
    ))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    bindings::sha256_impl(data)
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    bindings::pad_plaintext_impl(data)
}

#[wasm_bindgen]
pub fn unpad_plaintext(data: &[u8]) -> Vec<u8> {
    bindings::unpad_plaintext_impl(data)
}

// ---------------------------------------------------------------------------
// Drops
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn normalize_mnemonic(m: &str) -> String {
    bindings::normalize_mnemonic_impl(m)
}

#[wasm_bindgen]
pub fn derive_drop_lookup_key(mnemonic: &str) -> String {
    bindings::derive_drop_lookup_key_impl(mnemonic)
}

#[wasm_bindgen]
pub fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> Vec<u8> {
    bindings::derive_drop_wrapping_key_impl(mnemonic, version)
}

#[wasm_bindgen]
pub fn wrap_drop_key(wrapping_key: &[u8], drop_key: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::wrap_drop_key_impl(wrapping_key, drop_key))
}

#[wasm_bindgen]
pub fn unwrap_drop_key(wrapping_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsError> {
    to_js(bindings::unwrap_drop_key_impl(wrapping_key, wrapped))
}

#[wasm_bindgen]
pub fn generate_bip39_mnemonic() -> String {
    bindings::generate_bip39_mnemonic_impl()
}

#[wasm_bindgen]
pub fn validate_bip39_mnemonic(mnemonic: &str) -> bool {
    bindings::validate_bip39_mnemonic_impl(mnemonic)
}

#[wasm_bindgen]
pub fn derive_will_wrapping_key(mnemonic: &str, version: i32) -> Vec<u8> {
    bindings::derive_will_wrapping_key_impl(mnemonic, version)
}

#[wasm_bindgen]
pub fn derive_will_lookup_key(mnemonic: &str) -> String {
    bindings::derive_will_lookup_key_impl(mnemonic)
}

#[wasm_bindgen]
pub fn derive_recovery_keys(mnemonic: &str, version: i32) -> Result<JsValue, JsError> {
    let (wk, ak) = bindings::derive_recovery_keys_impl(mnemonic, version);
    to_js_val(json_to_js(&serde_json::json!({
        "wrapping_key": wk,
        "auth_key": ak,
    })))
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn build_envelope(filename: &str, data: &[u8], mime_type: &str) -> Vec<u8> {
    bindings::build_envelope_impl(filename, data, mime_type)
}

#[wasm_bindgen]
pub fn parse_envelope(data: &[u8], fallback_id: &str) -> Result<JsValue, JsError> {
    let (name, file_data) = bindings::parse_envelope_impl(data, fallback_id);
    to_js_val(json_to_js(&serde_json::json!({
        "name": name,
        "data": file_data,
    })))
}

/// Decrypt an encrypted blob (V0/V1 auto-detection), unpad, and return plaintext.
#[wasm_bindgen]
pub fn decrypt_blob(item_key: &[u8], blob_data: &[u8], user_id: &str) -> Result<Vec<u8>, JsError> {
    to_js(bindings::decrypt_blob_impl(item_key, blob_data, user_id))
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn parse_api_key(raw_key: &str) -> Result<JsValue, JsError> {
    let (prefix, secret) = to_js(bindings::parse_api_key_impl(raw_key))?;
    to_js_val(json_to_js(&serde_json::json!({
        "prefix": prefix,
        "secret": secret,
    })))
}

// ---------------------------------------------------------------------------
// High-level client orchestration (vault_core::client)
// ---------------------------------------------------------------------------

/// Prepare an encrypted item for upload.
/// Returns {encrypted_blob_b64, wrapped_key, nonce}.
#[wasm_bindgen]
pub fn prepare_item_create(
    master_key: &[u8],
    user_id: &str,
    label: &str,
    value: &str,
) -> Result<JsValue, JsError> {
    let (blob_b64, wrapped_key, nonce) = to_js(client_ops::prepare_item_create_impl(
        master_key, user_id, label, value,
    ))?;
    to_js_val(json_to_js(&serde_json::json!({
        "encrypted_blob_b64": blob_b64,
        "wrapped_key": wrapped_key,
        "nonce": nonce,
    })))
}

/// Decrypt an owned item's blob. Returns the parsed SecretBlob as JSON.
#[wasm_bindgen]
pub fn decrypt_owned_item(
    master_key: &[u8],
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
    blob_data: &[u8],
) -> Result<JsValue, JsError> {
    let blob: vault_core::envelope::SecretBlob = to_js(client_ops::decrypt_owned_item_impl(
        master_key,
        user_id,
        wrapped_key,
        nonce,
        blob_data,
    ))?;
    to_js_val(json_to_js(&blob))
}

/// Unwrap an owned item's key. Returns the 32-byte item key.
#[wasm_bindgen]
pub fn unwrap_owned_item_key(
    master_key: &[u8],
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    to_js(client_ops::unwrap_owned_item_key_impl(
        master_key,
        user_id,
        wrapped_key,
        nonce,
    ))
}

/// Prepare a grant: wrap an item key for a recipient.
/// Returns {grant_wrapped_key, ephemeral_pubkey}.
#[wasm_bindgen]
pub fn prepare_grant(item_key: &[u8], recipient_pubkey: &[u8]) -> Result<JsValue, JsError> {
    let (gwk, ep) = to_js(client_ops::prepare_grant_impl(item_key, recipient_pubkey))?;
    to_js_val(json_to_js(&serde_json::json!({
        "grant_wrapped_key": gwk,
        "ephemeral_pubkey": ep,
    })))
}

/// Decrypt a granted item's blob. Returns the parsed SecretBlob as JSON.
#[wasm_bindgen]
pub fn decrypt_granted_item(
    private_key: &[u8],
    recipient_pubkey: &[u8],
    ephemeral_pubkey: &[u8],
    grant_wrapped_key: &[u8],
    blob_data: &[u8],
    grantor_id: &str,
) -> Result<JsValue, JsError> {
    let blob: vault_core::envelope::SecretBlob = to_js(client_ops::decrypt_granted_item_impl(
        private_key,
        recipient_pubkey,
        ephemeral_pubkey,
        grant_wrapped_key,
        blob_data,
        grantor_id,
    ))?;
    to_js_val(json_to_js(&blob))
}

/// Prepare registration key material.
/// Returns {auth_key_hex, public_key, encrypted_private_key, client_salt, master_key}.
#[wasm_bindgen]
pub fn prepare_registration(password: &str) -> Result<JsValue, JsError> {
    let (auth_key_hex, public_key, encrypted_private_key, client_salt, master_key) =
        to_js(client_ops::prepare_registration_impl(password))?;
    to_js_val(json_to_js(&serde_json::json!({
        "auth_key_hex": auth_key_hex,
        "public_key": public_key,
        "encrypted_private_key": encrypted_private_key,
        "client_salt": client_salt,
        "master_key": master_key,
    })))
}

/// Prepare login key material.
/// Returns {master_key, auth_key_hex}.
#[wasm_bindgen]
pub fn prepare_login(password: &str, client_salt: &[u8]) -> Result<JsValue, JsError> {
    let (master_key, auth_key_hex) = to_js(client_ops::prepare_login_impl(password, client_salt))?;
    to_js_val(json_to_js(&serde_json::json!({
        "master_key": master_key,
        "auth_key_hex": auth_key_hex,
    })))
}

/// Encrypt a group name. Returns {encrypted_blob_b64, wrapped_key, nonce}.
#[wasm_bindgen]
pub fn encrypt_group(master_key: &[u8], user_id: &str, name: &str) -> Result<JsValue, JsError> {
    let (blob_b64, wrapped_key, nonce) =
        to_js(client_ops::encrypt_group_impl(master_key, user_id, name))?;
    to_js_val(json_to_js(&serde_json::json!({
        "encrypted_blob_b64": blob_b64,
        "wrapped_key": wrapped_key,
        "nonce": nonce,
    })))
}

/// Decrypt a group name from its encrypted blob.
#[wasm_bindgen]
pub fn decrypt_group_name(
    master_key: &[u8],
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
    encrypted_blob_b64: &str,
) -> Result<String, JsError> {
    to_js(client_ops::decrypt_group_name_impl(
        master_key,
        user_id,
        wrapped_key,
        nonce,
        encrypted_blob_b64,
    ))
}
