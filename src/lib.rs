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
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let result = serde_json::json!({
        "private_key": secret.to_bytes().to_vec(),
        "public_key": public.as_bytes().to_vec(),
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
    rand::thread_rng().fill_bytes(&mut key);
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
    let mut tr = [0u8; 32];
    tr.copy_from_slice(tree_root);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);

    Ok(vault_core::crypto::verify_notarization_signature(
        &pk,
        &ch,
        timestamp_millis,
        &tr,
        &sig,
    ))
}
