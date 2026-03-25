# vault-wasm

WebAssembly bindings for [BlindKeep](https://blindkeep.com) Vault cryptography.

Exposes [vault-core](https://github.com/blindkeep-vault/vault-core) primitives to JavaScript for use in the web UI. All crypto runs in the browser — the server never sees plaintext data or keys.

## Functions

| Function | Description |
|---|---|
| `derive_key(password, salt)` | Argon2id key derivation |
| `derive_subkey(master_key, info)` | HKDF-SHA256 subkey derivation |
| `encrypt(key, plaintext)` | XChaCha20-Poly1305 encryption |
| `decrypt(key, ciphertext, nonce)` | XChaCha20-Poly1305 decryption |
| `generate_random_key()` | 32-byte random key |
| `generate_keypair()` | X25519 keypair for grant sharing |
| `wrap_key_for_recipient(key, pubkey)` | Asymmetric key wrapping |
| `unwrap_key(privkey, ephemeral_pub, wrapped, nonce)` | Asymmetric key unwrapping |
| `check_policy(policy_json, view_count, operation)` | Grant policy evaluation |

## Build

Requires [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build for web
wasm-pack build --target web --out-dir pkg

# Build for bundler (webpack, etc.)
wasm-pack build --target bundler --out-dir pkg
```

Requires Rust 1.70+ with the `wasm32-unknown-unknown` target:

```bash
rustup target add wasm32-unknown-unknown
```

## Usage in JavaScript

```javascript
import init, { derive_key, encrypt, decrypt } from './pkg/vault_wasm.js';

await init();

const key = derive_key("my-password", new Uint8Array(16));
const { ciphertext, nonce } = encrypt(key, new TextEncoder().encode("secret"));
const plaintext = decrypt(key, ciphertext, nonce);
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
