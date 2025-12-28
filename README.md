[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Security](#security) · [Dependencies](#dependencies)

# Vault-CLI

**vault-cli** is an securely encrypted credential manager with vim-style TUI, built in Rust.

Self-hosted, local-first architecture - your credentials never touch our servers.

![image](https://github.com/user-attachments/assets/ddc328f0-61c5-40e2-9707-1b8beda5691e)

<a name="features"></a>
## ✨ Features

- **Secure Storage:** Per-credential encryption with ChaCha20-Poly1305 AEAD
- **Strong Key Derivation:** Argon2id with 19 MiB memory cost
- **Hierarchical Keys:** Master Key wraps DEK (Data Encryption Key), DEK encrypts credentials - enables password changes without re-encrypting data
    - **Master key** → **DEK (wrapped)** → **Credential keys**
- **Full-Text Search:** SQLite FTS5 for fast search
- **Search or filter by project/tag:** Organize your credentials and keys via tagging
- **Vim Keybindings:** Modal editing with hjkl navigation
- **TOTP Support:** Generate 2FA codes with countdown timer
- **Password Generator:** Configurable CSPRNG password generation
- **Password Strength Checker:** Evaluates the security of user passwords in real-time, providing feedback on complexity, and length to help users create stronger, safer passwords.
- **Audit Trail:** HMAC-signed logs for tamper detection
- **Auto-clear clipboard:** Automatically overwrite or wipe clipboard memory with 0-bytes (Zeroization) after 15 seconds
- **Auto-lock:** Automatically lock vault-cli after 5 minutes of inactivity

<a name="installation"></a>
## ⚡ Installation

Requires `rustc` to be installed on your system!

```bash
git clone https://github.com/iamKimlong/vaultcli
cd vaultcli

# One-liner
cargo build --release && sudo install -m 755 target/release/vault-cli /usr/local/bin/vault-cli

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

**📜 Note:** whenever you update the vault-cli, your credentials will remain unchanged unless you explicity delete them.

<a name="usage"></a>
## 🚀 Usage

### Normal Mode
| Key | Action |
|-----|--------|
| `j/k` or `↓/↑` | Navigate up/down |
| `gg` | Go to top |
| `G` | Go to bottom |
| `Enter` | View details |
| `n` | New credential |
| `e` | Edit credential |
| `dd` | Delete credential |
| `yy/c` | Copy password |
| `u` | Copy username |
| `t` | Copy TOTP |
| `s` | Toggle password visibility |
| `Ctrl-p` | Change master key |
| `Ctrl-l` | Clear message |
| `i` | View logs |
| `L` | Lock vault |
| `/` | Search |
| `:` | Command mode |
| `?` | Help |
| `q` | Quit |

### Commands
- `:q` - Quit
- `:new` - New credential
- `:project` - New project
- `:changepw` - Change master key
- `:gen` - Generate password
- `:audit` - Verify audit log integrity
- `:log` - View logs
- `:help` - Show help

<a name="security"></a>
## 🛡️ Security

### Encryption
- **ChaCha20-Poly1305** AEAD encryption
- **Argon2id** key derivation (19 MiB, 2 iterations) - resistant to GPU/ASIC attacks
- **Unique random salt** per vault, embedded in PHC string

### Key Architecture
- **Master Key** derived from your password via Argon2id
- **Data Encryption Key (DEK)** random 256-bit key that encrypts all credentials
- **Wrapped DEK** - DEK encrypted by Master Key, stored in database
- **Password changes** only re-wrap the DEK - no need to re-encrypt credentials

### Memory Protection
- **Zeroized memory** for sensitive data
- `mlock()`/`VirtualLock()` to prevent key material from swapping to disk
- `PR_SET_DUMPABLE=0` to prevent core dumps (Unix)

### Audit Trail
- **Audit Trail** all sensitive actions logged (unlock, create, read, copy, update, delete)
- **HMAC-SHA256** signatures on each log entry
- **Tamper detection** on unlock and via `:audit` command 
- **Detects** if attacker modifies or deletes log entries

### Miscellaneous
- **Auto-lock** after 5 minutes
- **Auto-wipe clipboard** after 15 seconds with zeroization

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
- [`secrecy`](https://crates.io/crates/secrecy)
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

### Platform

- [`libc`](https://crates.io/crates/libc) (Unix)
- [`windows-sys`](https://crates.io/crates/windows-sys) (Windows)
    Features: `Win32_System_Memory`

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
