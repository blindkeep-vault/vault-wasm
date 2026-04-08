use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    let master = vault_core::crypto::derive_master_key(password.as_bytes(), salt)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(master.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn derive_key_legacy(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    let master = vault_core::crypto::derive_master_key_legacy(password.as_bytes(), salt)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(master.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn derive_subkey(master_key: &[u8], info: &str) -> Result<Vec<u8>, JsError> {
    if master_key.len() != 32 {
        return Err(JsError::new("master key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(master_key);
    let master = vault_core::crypto::MasterKey::from_bytes(key_arr);
    let subkey = vault_core::crypto::derive_subkey(&master, info.as_bytes())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(subkey.to_vec())
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsError> {
    let (private_key, public_key) = vault_core::crypto::generate_x25519_keypair();
    let result = serde_json::json!({
        "private_key": private_key.to_vec(),
        "public_key": public_key.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wrap_key_for_recipient(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<JsValue, JsError> {
    if item_key.len() != 32 {
        return Err(JsError::new("item key must be 32 bytes"));
    }
    if recipient_pubkey.len() != 32 {
        return Err(JsError::new("recipient public key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(item_key);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);

    let wrapped = vault_core::crypto::wrap_key_for_recipient(&ik, &pk)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "wrapped_key": wrapped.wrapped_key,
        "ephemeral_pubkey": wrapped.ephemeral_pubkey.to_vec(),
        "nonce": wrapped.nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn unwrap_key(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    if privkey.len() != 32 {
        return Err(JsError::new("private key must be 32 bytes"));
    }
    if ephemeral_pub.len() != 32 {
        return Err(JsError::new("ephemeral public key must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(privkey);
    let mut ep = [0u8; 32];
    ep.copy_from_slice(ephemeral_pub);

    let key = vault_core::crypto::unwrap_key(&sk, &ep, wrapped, nonce)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

#[wasm_bindgen]
pub fn generate_random_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key.to_vec()
}

#[wasm_bindgen]
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<JsValue, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);

    let payload = vault_core::crypto::encrypt_item(&key_arr, plaintext)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "ciphertext": payload.ciphertext,
        "nonce": payload.nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);

    vault_core::crypto::decrypt_item(&key_arr, ciphertext, nonce)
        .map(|z| (*z).clone())
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_v1(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<JsValue, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);

    let payload = vault_core::crypto::encrypt_item_v1(&key_arr, plaintext, aad)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "ciphertext": payload.ciphertext,
        "nonce": payload.nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_auto(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);

    vault_core::crypto::decrypt_item_auto(&key_arr, ciphertext, nonce, aad)
        .map(|z| (*z).clone())
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wrap_key_for_recipient_v1(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<JsValue, JsError> {
    if item_key.len() != 32 {
        return Err(JsError::new("item key must be 32 bytes"));
    }
    if recipient_pubkey.len() != 32 {
        return Err(JsError::new("recipient public key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(item_key);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);

    let wrapped = vault_core::crypto::wrap_key_for_recipient_v1(&ik, &pk)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "wrapped_key": wrapped.wrapped_key,
        "ephemeral_pubkey": wrapped.ephemeral_pubkey.to_vec(),
        "nonce": wrapped.nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn unwrap_key_v1(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, JsError> {
    if privkey.len() != 32 {
        return Err(JsError::new("private key must be 32 bytes"));
    }
    if ephemeral_pub.len() != 32 {
        return Err(JsError::new("ephemeral public key must be 32 bytes"));
    }
    if recipient_pubkey.len() != 32 {
        return Err(JsError::new("recipient public key must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(privkey);
    let mut ep = [0u8; 32];
    ep.copy_from_slice(ephemeral_pub);
    let mut rpk = [0u8; 32];
    rpk.copy_from_slice(recipient_pubkey);

    let key = vault_core::crypto::unwrap_key_v1(&sk, &ep, wrapped, nonce, &rpk)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

/// Wrap an item key for a grant recipient (V1 key-bound).
/// Returns {grant_wrapped_key: nonce||ciphertext, ephemeral_pubkey: 32 bytes}.
#[wasm_bindgen]
pub fn wrap_key_for_grant(item_key: &[u8], recipient_pubkey: &[u8]) -> Result<JsValue, JsError> {
    if item_key.len() != 32 {
        return Err(JsError::new("item key must be 32 bytes"));
    }
    if recipient_pubkey.len() != 32 {
        return Err(JsError::new("recipient public key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(item_key);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);

    let (grant_wrapped_key, ephemeral_pubkey) = vault_core::crypto::wrap_key_for_grant(&ik, &pk)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "grant_wrapped_key": grant_wrapped_key,
        "ephemeral_pubkey": ephemeral_pubkey.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Unwrap a grant-format wrapped key (nonce||ciphertext). Auto-detects V0/V1.
#[wasm_bindgen]
pub fn unwrap_grant_key(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    grant_wrapped_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, JsError> {
    if privkey.len() != 32 {
        return Err(JsError::new("private key must be 32 bytes"));
    }
    if ephemeral_pub.len() != 32 {
        return Err(JsError::new("ephemeral public key must be 32 bytes"));
    }
    if recipient_pubkey.len() != 32 {
        return Err(JsError::new("recipient public key must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(privkey);
    let mut ep = [0u8; 32];
    ep.copy_from_slice(ephemeral_pub);
    let mut rpk = [0u8; 32];
    rpk.copy_from_slice(recipient_pubkey);

    let key = vault_core::crypto::unwrap_grant_key(&sk, &ep, grant_wrapped_key, &rpk)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

/// Decrypt a user's private key from stored format (nonce(24) || ciphertext).
#[wasm_bindgen]
pub fn decrypt_private_key(
    enc_key: &[u8],
    encrypted_private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    if enc_key.len() != 32 {
        return Err(JsError::new("encryption key must be 32 bytes"));
    }
    let mut ek = [0u8; 32];
    ek.copy_from_slice(enc_key);

    let key = vault_core::crypto::decrypt_private_key(&ek, encrypted_private_key)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

#[wasm_bindgen]
pub fn derive_subkey_salted(
    master_key: &[u8],
    salt: &[u8],
    info: &str,
) -> Result<Vec<u8>, JsError> {
    if master_key.len() != 32 {
        return Err(JsError::new("master key must be 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(master_key);
    let master = vault_core::crypto::MasterKey::from_bytes(key_arr);
    let subkey = vault_core::crypto::derive_subkey_salted(&master, salt, info.as_bytes())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(subkey.to_vec())
}

#[wasm_bindgen]
pub fn check_policy(policy_json: &str, view_count: i32, operation: &str) -> Result<bool, JsError> {
    let policy: vault_core::Policy =
        serde_json::from_str(policy_json).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(policy.is_access_allowed(chrono::Utc::now(), view_count, None, operation, None))
}

#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

#[wasm_bindgen]
pub fn verify_notarization(
    pubkey: &[u8],
    content_hash: &[u8],
    blob_hash: &[u8],
    timestamp_millis: i64,
    tree_root: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    if pubkey.len() != 32 {
        return Err(JsError::new("public key must be 32 bytes"));
    }
    if content_hash.len() != 32 {
        return Err(JsError::new("content_hash must be 32 bytes"));
    }
    if !blob_hash.is_empty() && blob_hash.len() != 32 {
        return Err(JsError::new("blob_hash must be empty or 32 bytes"));
    }
    if tree_root.len() != 32 {
        return Err(JsError::new("tree_root must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(JsError::new("signature must be 64 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pubkey);
    let mut ch = [0u8; 32];
    ch.copy_from_slice(content_hash);
    let bh = if blob_hash.len() == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(blob_hash);
        Some(b)
    } else {
        None
    };
    let mut tr = [0u8; 32];
    tr.copy_from_slice(tree_root);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);

    Ok(vault_core::crypto::verify_notarization_signature(
        &pk,
        &ch,
        bh.as_ref(),
        timestamp_millis,
        &tr,
        &sig,
    ))
}

/// Derive API key wrapping_key and auth_key from a 32-byte secret.
/// Returns {wrapping_key: Vec<u8>, auth_key: Vec<u8>}.
#[wasm_bindgen]
pub fn derive_api_key_keys(secret: &[u8]) -> Result<JsValue, JsError> {
    if secret.len() != 32 {
        return Err(JsError::new("secret must be 32 bytes"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(secret);
    let (wrapping_key, auth_key) =
        vault_core::crypto::derive_api_key_keys(&s).map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "wrapping_key": wrapping_key.to_vec(),
        "auth_key": auth_key.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

// --- Padding ---

#[wasm_bindgen]
pub fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    vault_core::padding::pad_plaintext(data)
}

#[wasm_bindgen]
pub fn unpad_plaintext(data: &[u8]) -> Vec<u8> {
    vault_core::padding::unpad(data).to_vec()
}

// --- Drops ---

#[wasm_bindgen]
pub fn normalize_mnemonic(m: &str) -> String {
    vault_core::drops::normalize_mnemonic(m)
}

#[wasm_bindgen]
pub fn derive_drop_lookup_key(mnemonic: &str) -> String {
    vault_core::drops::derive_drop_lookup_key(mnemonic)
}

#[wasm_bindgen]
pub fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> Vec<u8> {
    vault_core::drops::derive_drop_wrapping_key(mnemonic, version).to_vec()
}

#[wasm_bindgen]
pub fn wrap_drop_key(wrapping_key: &[u8], drop_key: &[u8]) -> Result<Vec<u8>, JsError> {
    if wrapping_key.len() != 32 {
        return Err(JsError::new("wrapping key must be 32 bytes"));
    }
    if drop_key.len() != 32 {
        return Err(JsError::new("drop key must be 32 bytes"));
    }
    let mut wk = [0u8; 32];
    wk.copy_from_slice(wrapping_key);
    let mut dk = [0u8; 32];
    dk.copy_from_slice(drop_key);
    vault_core::drops::wrap_drop_key(&wk, &dk).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn unwrap_drop_key(wrapping_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsError> {
    if wrapping_key.len() != 32 {
        return Err(JsError::new("wrapping key must be 32 bytes"));
    }
    let mut wk = [0u8; 32];
    wk.copy_from_slice(wrapping_key);
    vault_core::drops::unwrap_drop_key(&wk, wrapped)
        .map(|k| k.to_vec())
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_bip39_mnemonic() -> String {
    vault_core::drops::generate_bip39_mnemonic()
}

#[wasm_bindgen]
pub fn validate_bip39_mnemonic(mnemonic: &str) -> bool {
    vault_core::drops::validate_bip39_mnemonic(mnemonic)
}

#[wasm_bindgen]
pub fn derive_will_wrapping_key(mnemonic: &str, version: i32) -> Vec<u8> {
    vault_core::drops::derive_will_wrapping_key(mnemonic, version).to_vec()
}

#[wasm_bindgen]
pub fn derive_will_lookup_key(mnemonic: &str) -> String {
    vault_core::drops::derive_will_lookup_key(mnemonic)
}

#[wasm_bindgen]
pub fn derive_recovery_keys(mnemonic: &str, version: i32) -> Result<JsValue, JsError> {
    let (wrapping_key, auth_key) = vault_core::drops::derive_recovery_keys(mnemonic, version);
    let result = serde_json::json!({
        "wrapping_key": wrapping_key.to_vec(),
        "auth_key": auth_key.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn build_envelope(filename: &str, data: &[u8], mime_type: &str) -> Vec<u8> {
    vault_core::envelope::build_envelope(filename, data, mime_type)
}

#[wasm_bindgen]
pub fn parse_envelope(data: &[u8], fallback_id: &str) -> Result<JsValue, JsError> {
    let (name, file_data) = vault_core::envelope::parse_envelope(data, fallback_id);
    let result = serde_json::json!({
        "name": name,
        "data": file_data,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt an encrypted blob (V0/V1 auto-detection), unpad, and return plaintext.
#[wasm_bindgen]
pub fn decrypt_blob(item_key: &[u8], blob_data: &[u8], user_id: &str) -> Result<Vec<u8>, JsError> {
    if item_key.len() != 32 {
        return Err(JsError::new("item key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(item_key);
    let decrypted = vault_core::envelope::decrypt_blob_bytes(blob_data, &ik, user_id)
        .map_err(|e| JsError::new(&e.to_string()))?;
    // Unpad
    let unpadded = vault_core::padding::unpad(&decrypted);
    Ok(unpadded.to_vec())
}

// --- Unlock ---

#[wasm_bindgen]
pub fn parse_api_key(raw_key: &str) -> Result<JsValue, JsError> {
    let (prefix, secret) =
        vault_core::unlock::parse_api_key(raw_key).map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "prefix": prefix,
        "secret": secret.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Wrap a 32-byte key (e.g. API key private key) with a wrapping key.
/// Returns nonce(24) || ciphertext as a single byte array.
#[wasm_bindgen]
pub fn wrap_key_symmetric(wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, JsError> {
    if wrapping_key.len() != 32 {
        return Err(JsError::new("wrapping key must be 32 bytes"));
    }
    if key_to_wrap.len() != 32 {
        return Err(JsError::new("key to wrap must be 32 bytes"));
    }
    let mut wk = [0u8; 32];
    wk.copy_from_slice(wrapping_key);
    let mut ktw = [0u8; 32];
    ktw.copy_from_slice(key_to_wrap);
    let mk = vault_core::crypto::MasterKey::from_bytes(ktw);
    vault_core::crypto::wrap_master_key(&wk, &mk).map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// High-level client orchestration (vault_core::client)
// ---------------------------------------------------------------------------

fn mk_from_slice(key: &[u8]) -> Result<vault_core::crypto::MasterKey, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("master key must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key);
    Ok(vault_core::crypto::MasterKey::from_bytes(arr))
}

/// Prepare an encrypted item for upload.
/// Returns {encrypted_blob_b64, wrapped_key, nonce}.
#[wasm_bindgen]
pub fn prepare_item_create(
    master_key: &[u8],
    user_id: &str,
    label: &str,
    value: &str,
) -> Result<JsValue, JsError> {
    let mk = mk_from_slice(master_key)?;
    let p = vault_core::client::prepare_item_create(&mk, user_id, label, value, None)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "encrypted_blob_b64": p.encrypted_blob_b64,
        "wrapped_key": p.wrapped_key,
        "nonce": p.nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
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
    let mk = mk_from_slice(master_key)?;
    let blob = vault_core::client::decrypt_owned_item(&mk, user_id, wrapped_key, nonce, blob_data)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&blob).map_err(|e| JsError::new(&e.to_string()))
}

/// Unwrap an owned item's key. Returns the 32-byte item key.
#[wasm_bindgen]
pub fn unwrap_owned_item_key(
    master_key: &[u8],
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mk = mk_from_slice(master_key)?;
    let key = vault_core::client::unwrap_owned_item_key(&mk, user_id, wrapped_key, nonce)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

/// Prepare a grant: wrap an item key for a recipient.
/// Returns {grant_wrapped_key, ephemeral_pubkey}.
#[wasm_bindgen]
pub fn prepare_grant(item_key: &[u8], recipient_pubkey: &[u8]) -> Result<JsValue, JsError> {
    if item_key.len() != 32 || recipient_pubkey.len() != 32 {
        return Err(JsError::new("keys must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(item_key);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);
    let g =
        vault_core::client::prepare_grant(&ik, &pk).map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "grant_wrapped_key": g.grant_wrapped_key,
        "ephemeral_pubkey": g.ephemeral_pubkey.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
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
    if private_key.len() != 32 || recipient_pubkey.len() != 32 || ephemeral_pubkey.len() != 32 {
        return Err(JsError::new("keys must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_key);
    let mut rpk = [0u8; 32];
    rpk.copy_from_slice(recipient_pubkey);
    let mut ep = [0u8; 32];
    ep.copy_from_slice(ephemeral_pubkey);
    let blob = vault_core::client::decrypt_granted_item(
        &sk,
        &rpk,
        &ep,
        grant_wrapped_key,
        blob_data,
        grantor_id,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&blob).map_err(|e| JsError::new(&e.to_string()))
}

/// Prepare registration key material.
/// Returns {auth_key_hex, public_key, encrypted_private_key, client_salt}.
#[wasm_bindgen]
pub fn prepare_registration(password: &str) -> Result<JsValue, JsError> {
    let reg = vault_core::client::prepare_registration(password)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "auth_key_hex": reg.auth_key_hex,
        "public_key": reg.public_key.to_vec(),
        "encrypted_private_key": reg.encrypted_private_key,
        "client_salt": reg.client_salt,
        "master_key": reg.master_key.as_bytes().to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Prepare login key material.
/// Returns {master_key, auth_key_hex}.
#[wasm_bindgen]
pub fn prepare_login(password: &str, client_salt: &[u8]) -> Result<JsValue, JsError> {
    let login = vault_core::client::prepare_login(password, client_salt)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "master_key": login.master_key.as_bytes().to_vec(),
        "auth_key_hex": login.auth_key_hex,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypt a group name. Returns {encrypted_blob_b64, wrapped_key, nonce}.
#[wasm_bindgen]
pub fn encrypt_group(master_key: &[u8], user_id: &str, name: &str) -> Result<JsValue, JsError> {
    let mk = mk_from_slice(master_key)?;
    let (blob_b64, wrapped_key, nonce) = vault_core::client::encrypt_group(&mk, user_id, name)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let result = serde_json::json!({
        "encrypted_blob_b64": blob_b64,
        "wrapped_key": wrapped_key,
        "nonce": nonce.to_vec(),
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
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
    let mk = mk_from_slice(master_key)?;
    vault_core::client::decrypt_group_name(&mk, user_id, wrapped_key, nonce, encrypted_blob_b64)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypt a 32-byte link secret with a claim key using AES-256-GCM.
/// Returns iv(12) || ciphertext. Compatible with SubtleCrypto AES-GCM.
#[wasm_bindgen]
pub fn encrypt_claim_secret(claim_key: &[u8], link_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    if claim_key.len() != 32 {
        return Err(JsError::new("claim key must be 32 bytes"));
    }
    if link_secret.len() != 32 {
        return Err(JsError::new("link secret must be 32 bytes"));
    }
    let mut ck = [0u8; 32];
    ck.copy_from_slice(claim_key);
    let mut ls = [0u8; 32];
    ls.copy_from_slice(link_secret);
    vault_core::crypto::encrypt_claim_secret(&ck, &ls).map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt a 32-byte link secret from iv(12) || ciphertext using AES-256-GCM.
#[wasm_bindgen]
pub fn decrypt_claim_secret(claim_key: &[u8], claim_ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    if claim_key.len() != 32 {
        return Err(JsError::new("claim key must be 32 bytes"));
    }
    let mut ck = [0u8; 32];
    ck.copy_from_slice(claim_key);
    let result = vault_core::crypto::decrypt_claim_secret(&ck, claim_ciphertext)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(result.to_vec())
}
