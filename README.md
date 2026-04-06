# vault-wasm

WebAssembly bindings for [BlindKeep](https://blindkeep.com) vault-core cryptography. Enables browser-side zero-knowledge encryption without any server-side key access.

## What it exposes

All crypto operations run in the browser via WASM -- the server never sees plaintext or keys.

### Key derivation
- `derive_key(password, salt)` -- Argon2id master key derivation
- `derive_subkey(master_key, info)` -- HKDF-SHA256 subkey derivation
- `derive_subkey_salted(master_key, salt, info)` -- HKDF with explicit salt

### Encryption
- `encrypt(key, plaintext)` / `decrypt(key, ciphertext, nonce)` -- XChaCha20-Poly1305
- `encrypt_v1(key, plaintext, aad)` / `decrypt_auto(key, ciphertext, nonce, aad)` -- V1 with AAD

### Key wrapping (grants)
- `wrap_key_for_recipient(recipient_pubkey, item_key)` -- X25519 ECDH + HKDF
- `unwrap_key(private_key, ephemeral_pubkey, wrapped_key, nonce)` -- Reverse
- `wrap_key_for_grant(...)` / `unwrap_grant_key(...)` -- Grant-specific wrapping

### Drops
- `generate_bip39_mnemonic()` -- 12-word BIP39 passphrase
- `derive_drop_lookup_key(mnemonic)` -- HKDF lookup key
- `derive_drop_wrapping_key(mnemonic, version)` -- PBKDF2 wrapping key
- `wrap_drop_key(...)` / `unwrap_drop_key(...)` -- Drop key encryption

### Utilities
- `generate_keypair()` / `generate_random_key()` -- X25519 keypair, random 256-bit key
- `decrypt_private_key(enc_key, encrypted_private_key)` -- Unlock stored private key
- `pad_plaintext(data)` / `unpad_plaintext(data)` -- Bucket-sized random padding
- `sha256(data)` -- Hash computation
- `verify_notarization(cert_json, notary_pubkey)` -- Certificate verification
- `parse_api_key(raw_key)` / `derive_api_key_keys(secret)` -- API key handling

## Build

```bash
wasm-pack build --target web
```

Output goes to `pkg/` -- include in your web app as an ES module.

## Usage

```javascript
import init, { derive_key, encrypt, decrypt } from './pkg/vault_wasm.js';

await init();

const masterKey = derive_key(password, salt);
const { ciphertext, nonce } = encrypt(key, plaintext);
const plaintext = decrypt(key, ciphertext, nonce);
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
