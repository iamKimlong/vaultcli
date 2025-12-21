[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Security](#security) · [Dependencies](#dependencies)

# Vault-CLI

**vault-cli** is local-first encrypted credential manager with vim-style TUI, built in Rust.

![image](https://github.com/user-attachments/assets/417c24fa-8e47-48ea-956b-8a700827deab)

<a name="features"></a>
## ✨ Features

- **Secure Storage:** Per-credential encryption with ChaCha20-Poly1305 AEAD
- **Strong Key Derivation:** Argon2id with 19 MiB memory cost
- **Hierarchical Keys:** Master key → Project keys → Credential keys
- **Full-Text Search:** SQLite FTS5 for fast search
- **Search or filter by project/tag:** Organize your credentials and keys via tagging
- **Vim Keybindings:** Modal editing with hjkl navigation
- **TOTP Support:** Generate 2FA codes with countdown timer
- **Password Generator:** Configurable CSPRNG password generation
- **Password Strength Checker:** Evaluates the security of user passwords in real-time, providing feedback on complexity, and length to help users create stronger, safer passwords.
- **Audit Trail:** HMAC-signed logs for tamper detection
- **Auto-lock:** Automatically lock vault-cli after 5 minutes of inactivity

<a name="installation"></a>
## ⚡ Installation

```bash
git clone https://github.com/iamKimlong/vaultcli
cd vaultcli

# --------------------------------
# Option 1: Build manually
# --------------------------------
# Build the release binary
cargo build --release

# Local install (per-user)
mv ./target/release/vault-cli ~/.local/bin/vault-cli

# System-wide install
sudo install -m 755 target/release/vault-cli /usr/local/bin/vault-cli

# --------------------------------
# Option 2: Cargo-managed install
# --------------------------------
cargo install --path .   # ensure ~/.cargo/bin is in PATH
# Currently have bugs on Windows (unable to create password)

# --------------------------------
# Option 3: Test only (minimal)
# --------------------------------
cargo run
```

<a name="usage"></a>
## 🚀 Usage

### Normal Mode
| Key | Action |
|-----|--------|
| `j/k` | Navigate up/down |
| `gg` | Go to top |
| `G` | Go to bottom |
| `Enter` | View details |
| `n` | New credential |
| `dd` | Delete credential |
| `yy/c` | Copy password |
| `u` | Copy username |
| `t` | Copy TOTP |
| `s` | Toggle password visibility |
| `/` | Search |
| `:` | Command mode |
| `?` | Help |
| `q` | Quit |

### Commands
- `:q` - Quit
- `:new` - New credential
- `:project` - New project
- `:gen` - Generate password
- `:help` - Show help

<a name="security"></a>
## 🛡️ Security

- ChaCha20-Poly1305 encryption
- Argon2id key derivation (19 MiB, 2 iterations)
- Zeroized memory for sensitive data
- HMAC-SHA256 audit signatures
- Auto-lock after 5 minutes

## 🐞 Known Bugs

- Program exit on unlock (after auto-lock)
- Clipboard does not auto-clear properly
- Auto-lock sometimes lock earlier than set time (5 minutes)

<a name="dependencies"></a>
## ⚙️ Dependencies

### TUI

- [`ratatui`](https://crates.io/crates/ratatui)
- [`crossterm`](https://crates.io/crates/crossterm)

### Database

- [`rusqlite`](https://crates.io/crates/rusqlite)
    Features: `bundled`, `backup`

### Crypto

- [`argon2`](https://crates.io/crates/argon2)
- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
- [`hkdf`](https://crates.io/crates/hkdf)
- [`sha2`](https://crates.io/crates/sha2)
- [`hmac`](https://crates.io/crates/hmac)
- [`sha1`](https://crates.io/crates/sha1)
- [`rand`](https://crates.io/crates/rand)
- [`zeroize`](https://crates.io/crates/zeroize)
    Features: `derive`

### TOTP

- [`totp-rs`](https://crates.io/crates/totp-rs)
  Features: `otpauth`

### Clipboard

- [`arboard`](https://crates.io/crates/arboard)

### Serialization

- [`serde`](https://crates.io/crates/serde)
    Features: `derive`
- [`serde_json`](https://crates.io/crates/serde_json)

### Utilities

- [`chrono`](https://crates.io/crates/chrono)
    Features: `serde`
- [`uuid`](https://crates.io/crates/uuid)
    Features: `v4`
- [`hex`](https://crates.io/crates/hex)
- [`base64`](https://crates.io/crates/base64)
- [`dirs`](https://crates.io/crates/dirs)
- [`thiserror`](https://crates.io/crates/thiserror)
- [`anyhow`](https://crates.io/crates/anyhow)

### Development Dependencies

- [`tempfile`](https://crates.io/crates/tempfile)
