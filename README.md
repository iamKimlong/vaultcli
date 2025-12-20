<h4 align="center">
    <a href="#features">Features</a>
    ·
    <a href="#installation">Installation</a>
    ·
    <a href="#usage">Usage</a>
    ·
    <a href="#project-structure">Project Structure</a>
    ·
    <a href="#security">Security</a>
</h4>

**vault-cli** is local-first encrypted credential manager with vim-style TUI, built in Rust.

![image](https://github.com/user-attachments/assets/417c24fa-8e47-48ea-956b-8a700827deab)

## Features

- **Secure Storage:** Per-credential encryption with ChaCha20-Poly1305 AEAD
- **Strong Key Derivation:** Argon2id with 19 MiB memory cost
- **Hierarchical Keys:** Master key → Project keys → Credential keys
- **Full-Text Search:** SQLite FTS5 for fast search
- **Vim Keybindings:** Modal editing with hjkl navigation
- **TOTP Support:** Generate 2FA codes with countdown timer
- **Password Generator:** Configurable CSPRNG password generation
- **Audit Trail:** HMAC-signed logs for tamper detection
- **Auto-lock:** Automatically lock vault-cli after 5 minutes of inactivity

## Installation

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
```

## Usage

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

## Project Structure

```
src/
├── app.rs          # Application state
├── main.rs         # Entry point
├── crypto/         # Encryption, KDF, TOTP
├── db/             # SQLite + FTS5
├── input/          # Vim keybindings
├── ui/             # TUI components
└── vault/          # Business logic
```

## Security

- ChaCha20-Poly1305 encryption
- Argon2id key derivation (19 MiB, 2 iterations)
- Zeroized memory for sensitive data
- HMAC-SHA256 audit signatures
- Auto-lock after 5 minutes
