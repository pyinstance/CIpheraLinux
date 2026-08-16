use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use chrono::Utc;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use rand_core::{OsRng, RngCore};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const FORMAT_VERSION: u8 = 2;
const CLIPBOARD_CLEAR_SECONDS: u64 = 15;
const DEFAULT_AUTO_LOCK_MINUTES: u64 = 5;

const RESET: &str = "\x1b[0m";
const BLUE: &str = "\x1b[38;2;90;170;255m";
const BLUE_DIM: &str = "\x1b[38;2;80;135;190m";
const WHITE: &str = "\x1b[38;2;225;228;234m";
const GREY: &str = "\x1b[38;2;125;132;143m";
const GREEN: &str = "\x1b[38;2;105;205;145m";
const YELLOW: &str = "\x1b[38;2;235;190;95m";
const RED: &str = "\x1b[38;2;235;105;110m";

const BANNER: &str = r#"
⠀⠀⠀⠀⢀⡠⠤⠔⢲⢶⡖⠒⠤⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⡚⠁⢀⠀⠀⢄⢻⣿⠀⠀⠀⡙⣷⢤⡀⠀⠀⠀⠀⠀⠀
⠀⡜⢱⣇⠀⣧⢣⡀⠀⡀⢻⡇⠀⡄⢰⣿⣷⡌⣢⡀⠀⠀⠀⠀
⠸⡇⡎⡿⣆⠹⣷⡹⣄⠙⣽⣿⢸⣧⣼⣿⣿⣿⣶⣼⣆⠀⠀⠀
⣷⡇⣷⡇⢹⢳⡽⣿⡽⣷⡜⣿⣾⢸⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀
⣿⡇⡿⣿⠀⠣⠹⣾⣿⣮⠿⣞⣿⢸⣿⣛⢿⣿⡟⠯⠉⠙⠛⠓
⣿⣇⣷⠙⡇⠀⠁⠀⠉⣽⣷⣾⢿⢸⣿⠀⢸⣿⢿⠀⠀⠀⠀⠀
⡟⢿⣿⣷⣾⣆⠀⠀⠘⠘⠿⠛⢸⣼⣿⢖⣼⣿⠘⡆⠀⠀⠀⠀
⠃⢸⣿⣿⡘⠋⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡆⠇⠀⠀⠀⠀
⠀⢸⡿⣿⣇⠀⠈⠀⠤⠀⠀⢀⣿⣿⣿⣿⣿⣿⣧⢸⠀⠀⠀⠀
⠀⠈⡇⣿⣿⣷⣤⣀⠀⣀⠔⠋⣿⣿⣿⣿⣿⡟⣿⡞⡄⠀⠀⠀
⠀⠀⢿⢸⣿⣿⣿⣿⣿⡇⠀⢠⣿⡏⢿⣿⣿⡇⢸⣇⠇⠀⠀⠀
⠀⠀⢸⡏⣿⣿⣿⠟⠋⣀⠠⣾⣿⠡⠀⢉⢟⠷⢼⣿⣿⠀⠀⠀
⠀⠀⠈⣷⡏⡱⠁⠀⠊⠀⠀⣿⣏⣀⡠⢣⠃⠀⠀⢹⣿⡄⠀⠀
⠀⠀⠘⢼⣿⠀⢠⣤⣀⠉⣹⡿⠀⠁⠀⡸⠀⠀⠀⠈⣿⡇⠀⠀
"#;

#[derive(Debug, Serialize, Deserialize, Default)]
struct Vault {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Entry {
    id: String,
    title: String,
    username: String,
    email: String,
    password: String,
    url: String,
    notes: String,
    category: String,
    tags: Vec<String>,
    favourite: bool,
    created_at: String,
    updated_at: String,

    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    totp_secret: String,
    #[serde(default)]
    recovery_codes: Vec<String>,
    #[serde(default)]
    discord_token: String,
}

fn default_kind() -> String {
    "generic".into()
}

fn default_kdf_memory() -> u32 {
    64 * 1024
}
fn default_kdf_iterations() -> u32 {
    3
}
fn default_kdf_lanes() -> u32 {
    1
}
fn default_auto_lock() -> u64 {
    DEFAULT_AUTO_LOCK_MINUTES
}

#[derive(Debug, Clone)]
struct SecurityProfile {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    keyfile_required: bool,
    auto_lock_minutes: u64,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self {
            memory_kib: 128 * 1024,
            iterations: 4,
            lanes: 1,
            keyfile_required: false,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedVaultFile {
    version: u8,

    #[serde(default = "default_kdf_memory")]
    kdf_memory_kib: u32,
    #[serde(default = "default_kdf_iterations")]
    kdf_iterations: u32,
    #[serde(default = "default_kdf_lanes")]
    kdf_lanes: u32,
    #[serde(default)]
    keyfile_required: bool,
    #[serde(default = "default_auto_lock")]
    auto_lock_minutes: u64,

    salt: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedVaultFile {
    fn security_profile(&self) -> SecurityProfile {
        SecurityProfile {
            memory_kib: self.kdf_memory_kib,
            iterations: self.kdf_iterations,
            lanes: self.kdf_lanes,
            keyfile_required: self.keyfile_required,
            auto_lock_minutes: self.auto_lock_minutes,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProviderScan {
    provider: String,
    status: String,
    findings: usize,
    note: String,
    raw: Value,
}

#[derive(Debug, Serialize)]
struct BreachScanResult {
    email: String,
    scanned_at: String,
    providers: Vec<ProviderScan>,
    normalized_breaches: Vec<Value>,
}

fn main() -> Result<()> {
    splash();

    let vault_path = vault_path()?;
    prepare_storage(&vault_path)?;
    harden_file_permissions_if_needed(&vault_path)?;

    let (mut vault, salt, mut master_password, mut security) = if vault_path.exists() {
        unlock_existing_vault(&vault_path)?
    } else {
        create_new_vault(&vault_path)?
    };

    loop {
        draw_home(&vault);

        let options = [
            "Vault",
            "Add entry",
            "Search",
            "Generate password",
            "Password health",
            "Breach scanner",
            "Backups",
            "Security",
            "Lock / Exit",
        ];

        let started_waiting = Instant::now();

        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{BLUE}Select{RESET}"))
            .items(&options)
            .default(0)
            .interact()?;

        if security.auto_lock_minutes > 0
            && started_waiting.elapsed()
                >= Duration::from_secs(security.auto_lock_minutes.saturating_mul(60))
        {
            warning_box("Session timeout reached. CIphera is locking.");
            break;
        }

        match choice {
            0 => vault_menu(&mut vault, &vault_path, &salt, &master_password, &security)?,
            1 => {
                if add_entry(&mut vault)? {
                    save_vault(&vault_path, &master_password, &salt, &security, &vault)?;
                    success("Entry saved");
                }
            }
            2 => search_menu(&mut vault, &vault_path, &salt, &master_password, &security)?,
            3 => generator_menu()?,
            4 => {
                password_health(&vault);
                pause();
            }
            5 => breach_scanner_menu(&vault)?,
            6 => backups_menu(&mut vault, &vault_path, &master_password, &security)?,
            7 => security_menu(&vault, &vault_path, &salt, &master_password, &mut security)?,
            8 => break,
            _ => {}
        }
    }

    master_password.zeroize();
    clear_screen();
    println!("{BLUE}CIphera locked.{RESET}");
    Ok(())
}

fn clear_screen() {
    print!("\x1B[2J\x1B[H");
    let _ = io::stdout().flush();
}

fn splash() {
    clear_screen();
    println!("{BLUE}{BANNER}{RESET}");
    println!("{WHITE}                 CIphera CLI Password Manager{RESET}");
    println!("{GREY}                 secure • local • encrypted{RESET}\n");
}

fn draw_home(vault: &Vault) {
    clear_screen();
    println!("{WHITE}                    CIphera CLI Password Manager{RESET}\n");

    let (weak, reused) = password_health_counts(vault);
    let health_color = if weak == 0 && reused == 0 {
        GREEN
    } else {
        YELLOW
    };

    println!(
        "{BLUE_DIM}╭─ VAULT STATUS ───────────────────────────────────────────────────╮{RESET}"
    );
    println!(
        "{BLUE_DIM}│{RESET} {GREEN}● UNLOCKED{RESET}    {WHITE}{} entries{RESET}    {GREY}Clipboard: {}s{RESET}    {}Health: {}/{}{RESET}",
        vault.entries.len(),
        CLIPBOARD_CLEAR_SECONDS,
        health_color,
        weak,
        reused
    );
    println!(
        "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}\n"
    );

    println!(
        "{BLUE_DIM}╭─ MAIN MENU ─────────────────────────────────────────────────────╮{RESET}"
    );
    println!("{BLUE_DIM}│{RESET}  {GREY}Use ↑ ↓ to move and Enter to select{RESET}                            {BLUE_DIM}│{RESET}");
    println!(
        "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}"
    );
}

fn pause() {
    let _: String = Input::new()
        .with_prompt("Press Enter to continue")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();
}

fn success(message: &str) {
    println!("\n{GREEN}╭─ SUCCESS ─────────────────────────────────────────╮{RESET}");
    for line in message.lines() {
        println!("{GREEN}│{RESET} {line}");
    }
    println!("{GREEN}╰───────────────────────────────────────────────────╯{RESET}");
    pause();
}

fn warning_box(message: &str) {
    println!("\n{YELLOW}╭─ WARNING ─────────────────────────────────────────╮{RESET}");
    for line in message.lines() {
        println!("{YELLOW}│{RESET} {line}");
    }
    println!("{YELLOW}╰───────────────────────────────────────────────────╯{RESET}");
}

fn error_box(message: &str) {
    println!("\n{RED}╭─ ERROR ───────────────────────────────────────────╮{RESET}");
    for line in message.lines() {
        println!("{RED}│{RESET} {line}");
    }
    println!("{RED}╰───────────────────────────────────────────────────╯{RESET}");
}

fn vault_path() -> Result<PathBuf> {
    let data = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("Could not determine local data directory"))?;
    Ok(data.join("ciphera").join("vault.ciphera"))
}

fn config_dir() -> Result<PathBuf> {
    let config =
        dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(config.join("ciphera"))
}

fn default_keyfile_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("ciphera.key"))
}

fn prepare_storage(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("Invalid vault path"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

    let cfg = config_dir()?;
    fs::create_dir_all(&cfg)?;
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn harden_file_permissions_if_needed(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mode = fs::metadata(path)?.mode() & 0o777;

    if mode != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn read_envelope(path: &Path) -> Result<EncryptedVaultFile> {
    let raw = fs::read(path).context("Could not read vault")?;
    let file: EncryptedVaultFile =
        serde_json::from_slice(&raw).context("Invalid vault envelope")?;
    Ok(file)
}

fn create_new_vault(path: &Path) -> Result<(Vault, Vec<u8>, String, SecurityProfile)> {
    println!("{BLUE_DIM}╭─ CREATE VAULT ───────────────────────────────────╮{RESET}");
    println!(
        "{BLUE_DIM}│{RESET} New vaults use the hardened CIphera v2 format.    {BLUE_DIM}│{RESET}"
    );
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}\n");

    let password = loop {
        let p1 = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Create master password (minimum 16 characters)")
            .interact()?;

        if p1.chars().count() < 16 {
            println!("{RED}Master password must contain at least 16 characters.{RESET}\n");
            continue;
        }

        let p2 = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm master password")
            .interact()?;

        if p1 != p2 {
            println!("{RED}Passwords do not match.{RESET}\n");
            continue;
        }

        break p1;
    };

    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let security = SecurityProfile::default();
    let vault = Vault::default();
    save_vault(path, &password, &salt, &security, &vault)?;

    println!("\n{GREEN}Vault created successfully.{RESET}");
    println!(
        "{GREY}Argon2id: {} MiB / {} iterations / {} lane{RESET}",
        security.memory_kib / 1024,
        security.iterations,
        security.lanes
    );
    pause();

    Ok((vault, salt, password, security))
}

fn unlock_existing_vault(path: &Path) -> Result<(Vault, Vec<u8>, String, SecurityProfile)> {
    let envelope = read_envelope(path)?;
    let profile = envelope.security_profile();

    if profile.keyfile_required {
        let keyfile = resolve_keyfile_path()?;
        if !keyfile.exists() {
            error_box(&format!(
                "This vault requires a CIphera keyfile.\nExpected: {}\nYou can override this with CIPHERA_KEYFILE.",
                keyfile.display()
            ));
            return Err(anyhow!("Required keyfile is missing"));
        }
    }

    loop {
        let password = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Master password")
            .interact()?;

        match load_vault(path, &password) {
            Ok((vault, salt, security)) => return Ok((vault, salt, password, security)),
            Err(_) => println!(
                "{RED}Incorrect password, missing/wrong keyfile, or damaged vault.{RESET}\n"
            ),
        }
    }
}

fn resolve_keyfile_path() -> Result<PathBuf> {
    if let Ok(value) = env::var("CIPHERA_KEYFILE") {
        return Ok(PathBuf::from(value));
    }

    default_keyfile_path()
}

fn read_keyfile(profile: &SecurityProfile) -> Result<Vec<u8>> {
    if !profile.keyfile_required {
        return Ok(Vec::new());
    }

    let path = resolve_keyfile_path()?;
    let bytes =
        fs::read(&path).with_context(|| format!("Could not read keyfile {}", path.display()))?;

    if bytes.len() < 32 {
        return Err(anyhow!("CIphera keyfile is invalid or too short"));
    }

    Ok(bytes)
}

fn argon2_for(profile: &SecurityProfile) -> Result<Argon2<'static>> {
    let params = Params::new(
        profile.memory_kib,
        profile.iterations,
        profile.lanes,
        Some(32),
    )
    .map_err(|e| anyhow!("Argon2 parameter error: {e}"))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn derive_key(password: &str, salt: &[u8], profile: &SecurityProfile) -> Result<[u8; 32]> {
    let mut keyfile = read_keyfile(profile)?;

    let mut secret = Vec::with_capacity(password.len() + keyfile.len() + 32);
    secret.extend_from_slice(password.as_bytes());
    secret.extend_from_slice(b"\x00CIphera-keyfile\x00");
    secret.extend_from_slice(&keyfile);

    let mut key = [0u8; 32];

    argon2_for(profile)?
        .hash_password_into(&secret, salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {e}"))?;

    secret.zeroize();
    keyfile.zeroize();

    Ok(key)
}

fn save_vault(
    path: &Path,
    password: &str,
    salt: &[u8],
    profile: &SecurityProfile,
    vault: &Vault,
) -> Result<()> {
    let mut plaintext = serde_json::to_vec(vault)?;
    let mut key = derive_key(password, salt, profile)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid encryption key"))?;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow!("Vault encryption failed"))?;

    plaintext.zeroize();
    key.zeroize();

    let file = EncryptedVaultFile {
        version: FORMAT_VERSION,
        kdf_memory_kib: profile.memory_kib,
        kdf_iterations: profile.iterations,
        kdf_lanes: profile.lanes,
        keyfile_required: profile.keyfile_required,
        auto_lock_minutes: profile.auto_lock_minutes,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    };

    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(&file)?)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

fn load_vault(path: &Path, password: &str) -> Result<(Vault, Vec<u8>, SecurityProfile)> {
    let file = read_envelope(path)?;

    if file.version != 1 && file.version != FORMAT_VERSION {
        return Err(anyhow!("Unsupported vault format version {}", file.version));
    }

    let profile = file.security_profile();
    let salt = B64.decode(file.salt)?;
    let nonce = B64.decode(file.nonce)?;
    let ciphertext = B64.decode(file.ciphertext)?;

    if nonce.len() != 24 {
        return Err(anyhow!("Invalid nonce"));
    }

    let mut key = derive_key(password, &salt, &profile)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid encryption key"))?;

    let mut plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("Vault authentication failed"))?;

    key.zeroize();

    let vault: Vault =
        serde_json::from_slice(&plaintext).context("Invalid decrypted vault data")?;

    plaintext.zeroize();

    Ok((vault, salt, profile))
}

fn add_entry(vault: &mut Vault) -> Result<bool> {
    clear_screen();
    println!("{BLUE_DIM}╭─ ADD ENTRY ──────────────────────────────────────╮{RESET}");
    println!(
        "{BLUE_DIM}│{RESET} Choose a normal login or a Discord account.      {BLUE_DIM}│{RESET}"
    );
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}\n");

    let types = ["Generic login", "Discord account", "Cancel"];
    let kind_choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Entry type")
        .items(&types)
        .default(0)
        .interact()?;

    if kind_choice == 2 {
        return Ok(false);
    }

    let is_discord = kind_choice == 1;

    let title: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Title")
        .default(if is_discord {
            "Discord".into()
        } else {
            "New Login".into()
        })
        .interact_text()?;

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .allow_empty(true)
        .interact_text()?;

    let email: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Email")
        .allow_empty(true)
        .interact_text()?;

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .allow_empty_password(true)
        .interact()?;

    let url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("URL")
        .default(if is_discord {
            "https://discord.com".into()
        } else {
            String::new()
        })
        .allow_empty(true)
        .interact_text()?;

    let category: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Category")
        .default(if is_discord {
            "Social".into()
        } else {
            "General".into()
        })
        .interact_text()?;

    let tags_raw: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Tags (comma separated)")
        .allow_empty(true)
        .interact_text()?;

    let notes: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Notes")
        .allow_empty(true)
        .interact_text()?;

    let mut totp_secret = String::new();
    let mut recovery_codes = Vec::new();
    let mut discord_token = String::new();

    if is_discord {
        warning_box(
            "Discord recovery information is optional.\n\
             Session tokens are highly sensitive credentials.\n\
             CIphera NEVER scans Discord, Firefox, browser data or system files.",
        );

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Store a TOTP/2FA secret manually?")
            .default(false)
            .interact()?
        {
            totp_secret = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("TOTP secret (hidden)")
                .allow_empty_password(true)
                .interact()?;
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Store recovery/backup codes?")
            .default(false)
            .interact()?
        {
            let raw: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Recovery codes (comma separated)")
                .allow_empty(true)
                .interact_text()?;

            recovery_codes = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to manually store your Discord session token?")
            .default(false)
            .interact()?
        {
            warning_box(
                "Discord session tokens are sensitive account credentials.\n\
                 Anyone with the token may be able to access the account.\n\
                 \n\
                 CIphera does not extract tokens from Discord, Firefox,\n\
                 browser storage, LevelDB, developer tools, or other applications.\n\
                 \n\
                 If you already have your own token legitimately,\n\
                 you can paste it manually into the encrypted vault.",
            );

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("I understand and want to continue")
                .default(false)
                .interact()?
            {
                discord_token = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Discord token (hidden)")
                    .allow_empty_password(true)
                    .interact()?;
            }
        }
    }

    let now = Utc::now().to_rfc3339();

    vault.entries.push(Entry {
        id: new_id(),
        title: title.trim().to_string(),
        username: username.trim().to_string(),
        email: email.trim().to_string(),
        password,
        url: url.trim().to_string(),
        notes,
        category: category.trim().to_string(),
        tags: parse_tags(&tags_raw),
        favourite: false,
        created_at: now.clone(),
        updated_at: now,
        kind: if is_discord {
            "discord".into()
        } else {
            "generic".into()
        },
        totp_secret,
        recovery_codes,
        discord_token,
    });

    Ok(true)
}

fn vault_menu(
    vault: &mut Vault,
    path: &Path,
    salt: &[u8],
    master: &str,
    security: &SecurityProfile,
) -> Result<()> {
    if vault.entries.is_empty() {
        warning_box("Your vault is empty. Use Add entry first.");
        pause();
        return Ok(());
    }

    loop {
        clear_screen();
        println!(
            "{BLUE_DIM}╭─ VAULT ──────────────────────────────────────────────────────────╮{RESET}"
        );

        let mut indexes: Vec<usize> = (0..vault.entries.len()).collect();
        indexes.sort_by_key(|&i| {
            (
                !vault.entries[i].favourite,
                vault.entries[i].title.to_lowercase(),
            )
        });

        let mut labels: Vec<String> = indexes
            .iter()
            .map(|&i| {
                let e = &vault.entries[i];
                let star = if e.favourite { "★" } else { " " };
                let kind = if e.kind == "discord" {
                    "Discord"
                } else {
                    &e.category
                };
                format!("{star} {:<22}  {:<18}  {kind}", e.title, e.username)
            })
            .collect();

        labels.push("← Back".into());

        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{BLUE}Vault{RESET}"))
            .items(&labels)
            .default(0)
            .interact()?;

        println!(
            "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}"
        );

        if choice == labels.len() - 1 {
            return Ok(());
        }

        entry_menu(vault, indexes[choice], path, salt, master, security)?;
    }
}

fn entry_menu(
    vault: &mut Vault,
    index: usize,
    path: &Path,
    salt: &[u8],
    master: &str,
    security: &SecurityProfile,
) -> Result<()> {
    loop {
        if index >= vault.entries.len() {
            return Ok(());
        }

        clear_screen();
        let e = &vault.entries[index];

        println!(
            "{BLUE_DIM}╭─ ENTRY DETAILS ──────────────────────────────────────────────────╮{RESET}"
        );
        println!("{BLUE_DIM}│{RESET} {WHITE}Title:{RESET}       {}", e.title);
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Type:{RESET}        {}",
            if e.kind == "discord" {
                "Discord account"
            } else {
                "Generic login"
            }
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Username:{RESET}    {}",
            empty(&e.username)
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Email:{RESET}       {}",
            empty(&e.email)
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Password:{RESET}    {}",
            if e.password.is_empty() {
                "(empty)"
            } else {
                "••••••••••••"
            }
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}URL:{RESET}         {}",
            empty(&e.url)
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Category:{RESET}    {}",
            empty(&e.category)
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Tags:{RESET}        {}",
            if e.tags.is_empty() {
                "—".into()
            } else {
                e.tags.join(", ")
            }
        );
        println!(
            "{BLUE_DIM}│{RESET} {WHITE}Favourite:{RESET}   {}",
            if e.favourite { "Yes ★" } else { "No" }
        );

        if e.kind == "discord" {
            println!("{BLUE_DIM}│{RESET}");
            println!("{BLUE_DIM}│{RESET} {BLUE}Discord recovery{RESET}");
            println!(
                "{BLUE_DIM}│{RESET} TOTP secret:     {}",
                if e.totp_secret.is_empty() {
                    "not stored"
                } else {
                    "stored • hidden"
                }
            );
            println!(
                "{BLUE_DIM}│{RESET} Recovery codes:  {}",
                if e.recovery_codes.is_empty() {
                    "not stored".into()
                } else {
                    format!("{} stored", e.recovery_codes.len())
                }
            );
            println!(
                "{BLUE_DIM}│{RESET} Session token:   {}",
                if e.discord_token.is_empty() {
                    "not stored"
                } else {
                    "stored • hidden"
                }
            );
        }

        println!("{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}\n");

        let mut options = vec![
            "Copy username",
            "Copy password",
            "Reveal password",
            "Edit",
            "Toggle favourite",
        ];

        if e.kind == "discord" && !e.discord_token.is_empty() {
            options.push("Reveal Discord token");
            options.push("Copy Discord token");
        }

        options.push("Delete");
        options.push("Back");

        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{BLUE}Action{RESET}"))
            .items(&options)
            .default(0)
            .interact()?;

        let mut cursor = 0usize;

        if choice == cursor {
            copy_to_clipboard(&vault.entries[index].username)?;
            success(&format!(
                "Username copied. Clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s."
            ));
            continue;
        }
        cursor += 1;

        if choice == cursor {
            copy_to_clipboard(&vault.entries[index].password)?;
            success(&format!(
                "Password copied. Clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s."
            ));
            continue;
        }
        cursor += 1;

        if choice == cursor {
            println!(
                "\n{YELLOW}Password:{RESET} {}",
                vault.entries[index].password
            );
            pause();
            continue;
        }
        cursor += 1;

        if choice == cursor {
            edit_entry(&mut vault.entries[index])?;
            save_vault(path, master, salt, security, vault)?;
            success("Entry updated");
            continue;
        }
        cursor += 1;

        if choice == cursor {
            let favourite = {
                let e = &mut vault.entries[index];
                e.favourite = !e.favourite;
                e.updated_at = Utc::now().to_rfc3339();
                e.favourite
            };

            save_vault(path, master, salt, security, vault)?;
            success(if favourite {
                "Added to favourites"
            } else {
                "Removed from favourites"
            });
            continue;
        }
        cursor += 1;

        let is_discord_with_token = {
            let e = &vault.entries[index];
            e.kind == "discord" && !e.discord_token.is_empty()
        };

        if is_discord_with_token {
            if choice == cursor {
                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Reveal the Discord token? Treat it like a password")
                    .default(false)
                    .interact()?
                {
                    println!(
                        "\n{YELLOW}Discord token:{RESET} {}",
                        vault.entries[index].discord_token
                    );
                    pause();
                }
                continue;
            }
            cursor += 1;

            if choice == cursor {
                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Copy the Discord token to the clipboard?")
                    .default(false)
                    .interact()?
                {
                    copy_to_clipboard(&vault.entries[index].discord_token)?;
                    success(&format!(
                        "Discord token copied. Clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s."
                    ));
                }
                continue;
            }
            cursor += 1;
        }

        if choice == cursor {
            let title = vault.entries[index].title.clone();

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Delete '{title}' permanently?"))
                .default(false)
                .interact()?
            {
                vault.entries.remove(index);
                save_vault(path, master, salt, security, vault)?;
                success("Entry deleted");
                return Ok(());
            }
            continue;
        }
        cursor += 1;

        if choice == cursor {
            return Ok(());
        }
    }
}

fn edit_entry(entry: &mut Entry) -> Result<()> {
    clear_screen();
    println!("{BLUE_DIM}╭─ EDIT ENTRY ─────────────────────────────────────╮{RESET}");
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}\n");

    let title: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Title")
        .with_initial_text(&entry.title)
        .interact_text()?;

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .with_initial_text(&entry.username)
        .allow_empty(true)
        .interact_text()?;

    let email: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Email")
        .with_initial_text(&entry.email)
        .allow_empty(true)
        .interact_text()?;

    let url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("URL")
        .with_initial_text(&entry.url)
        .allow_empty(true)
        .interact_text()?;

    let category: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Category")
        .with_initial_text(&entry.category)
        .interact_text()?;

    let tags: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Tags")
        .with_initial_text(entry.tags.join(", "))
        .allow_empty(true)
        .interact_text()?;

    let notes: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Notes")
        .with_initial_text(&entry.notes)
        .allow_empty(true)
        .interact_text()?;

    entry.title = title;
    entry.username = username;
    entry.email = email;
    entry.url = url;
    entry.category = category;
    entry.tags = parse_tags(&tags);
    entry.notes = notes;

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Change password?")
        .default(false)
        .interact()?
    {
        entry.password = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("New password")
            .allow_empty_password(true)
            .interact()?;
    }

    if entry.kind == "discord" {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Replace TOTP secret?")
            .default(false)
            .interact()?
        {
            entry.totp_secret = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("TOTP secret (hidden)")
                .allow_empty_password(true)
                .interact()?;
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Replace recovery codes?")
            .default(false)
            .interact()?
        {
            let raw: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Recovery codes (comma separated)")
                .allow_empty(true)
                .interact_text()?;

            entry.recovery_codes = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Replace the manually stored Discord token?")
            .default(false)
            .interact()?
        {
            warning_box("CIphera does not extract Discord tokens automatically.\nOnly paste your own sensitive credential.");

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("I understand and want to continue")
                .default(false)
                .interact()?
            {
                entry.discord_token = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Discord token (hidden)")
                    .allow_empty_password(true)
                    .interact()?;
            }
        }
    }

    entry.updated_at = Utc::now().to_rfc3339();
    Ok(())
}

fn search_menu(
    vault: &mut Vault,
    path: &Path,
    salt: &[u8],
    master: &str,
    security: &SecurityProfile,
) -> Result<()> {
    let query: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Search")
        .interact_text()?;

    let q = query.to_lowercase();

    let indexes: Vec<usize> = vault
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.title.to_lowercase().contains(&q)
                || e.username.to_lowercase().contains(&q)
                || e.email.to_lowercase().contains(&q)
                || e.url.to_lowercase().contains(&q)
                || e.category.to_lowercase().contains(&q)
                || e.tags.iter().any(|tag| tag.to_lowercase().contains(&q))
        })
        .map(|(i, _)| i)
        .collect();

    if indexes.is_empty() {
        warning_box("No matching entries found.");
        pause();
        return Ok(());
    }

    let labels: Vec<String> = indexes
        .iter()
        .map(|&i| format!("{} • {}", vault.entries[i].title, vault.entries[i].username))
        .collect();

    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Results")
        .items(&labels)
        .default(0)
        .interact()?;

    entry_menu(vault, indexes[choice], path, salt, master, security)
}

fn generator_menu() -> Result<()> {
    clear_screen();
    println!("{BLUE_DIM}╭─ PASSWORD GENERATOR ─────────────────────────────╮{RESET}");
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}\n");

    let length: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Length")
        .default(24)
        .validate_with(|v: &usize| -> std::result::Result<(), &str> {
            if *v < 12 || *v > 256 {
                Err("Choose a length from 12 to 256")
            } else {
                Ok(())
            }
        })
        .interact_text()?;

    let symbols = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Include symbols?")
        .default(true)
        .interact()?;

    let password = generate_password(length, symbols);
    println!("\n{BLUE_DIM}╭─ GENERATED ──────────────────────────────────────╮{RESET}");
    println!("{BLUE_DIM}│{RESET} {WHITE}{password}{RESET}");
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}");

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Copy to clipboard?")
        .default(true)
        .interact()?
    {
        copy_to_clipboard(&password)?;
        println!("{GREEN}Copied. Clears in {CLIPBOARD_CLEAR_SECONDS}s.{RESET}");
    }

    pause();
    Ok(())
}

fn generate_password(length: usize, symbols: bool) -> String {
    const BASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";

    let mut chars = BASE.to_vec();
    if symbols {
        chars.extend_from_slice(SYMBOLS);
    }

    let n = chars.len() as u32;
    let zone = u32::MAX - (u32::MAX % n);
    let mut out = String::with_capacity(length);

    while out.len() < length {
        let value = OsRng.next_u32();
        if value < zone {
            out.push(chars[(value % n) as usize] as char);
        }
    }

    out
}

fn password_health(vault: &Vault) {
    clear_screen();
    let (weak, reused) = password_health_counts(vault);

    println!("{BLUE_DIM}╭─ PASSWORD HEALTH ────────────────────────────────╮{RESET}");
    println!(
        "{BLUE_DIM}│{RESET} Total entries:     {}",
        vault.entries.len()
    );
    println!("{BLUE_DIM}│{RESET} Weak passwords:    {weak}");
    println!("{BLUE_DIM}│{RESET} Reused passwords:  {reused}");
    println!("{BLUE_DIM}╰──────────────────────────────────────────────────╯{RESET}");

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in &vault.entries {
        if !e.password.is_empty() {
            *counts.entry(e.password.as_str()).or_insert(0) += 1;
        }
    }

    for e in &vault.entries {
        if !e.password.is_empty() && e.password.chars().count() < 16 {
            println!("{YELLOW}Weak:{RESET} {}", e.title);
        }

        if !e.password.is_empty() && counts.get(e.password.as_str()).copied().unwrap_or(0) > 1 {
            println!("{RED}Reused:{RESET} {}", e.title);
        }
    }
}

fn password_health_counts(vault: &Vault) -> (usize, usize) {
    let weak = vault
        .entries
        .iter()
        .filter(|e| !e.password.is_empty() && e.password.chars().count() < 16)
        .count();

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in &vault.entries {
        if !e.password.is_empty() {
            *counts.entry(e.password.as_str()).or_insert(0) += 1;
        }
    }

    let reused = vault
        .entries
        .iter()
        .filter(|e| {
            !e.password.is_empty() && counts.get(e.password.as_str()).copied().unwrap_or(0) > 1
        })
        .count();

    (weak, reused)
}

fn breach_scanner_menu(vault: &Vault) -> Result<()> {
    let mut emails: Vec<String> = vault
        .entries
        .iter()
        .map(|e| e.email.trim())
        .filter(|e| !e.is_empty())
        .map(|e| e.to_lowercase())
        .collect();

    emails.sort();
    emails.dedup();

    if emails.is_empty() {
        warning_box("No email addresses are stored in the vault.");
        pause();
        return Ok(());
    }

    clear_screen();
    println!(
        "{BLUE_DIM}╭─ BREACH SCANNER ────────────────────────────────────────────────╮{RESET}"
    );
    println!("{BLUE_DIM}│{RESET} Only the selected email address is sent to breach providers.  {BLUE_DIM}│{RESET}");
    println!("{BLUE_DIM}│{RESET} Passwords, tokens, recovery codes and vault data are not sent. {BLUE_DIM}│{RESET}");
    println!(
        "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}\n"
    );

    let mut choices = emails.clone();
    choices.push("← Back".into());

    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Email to scan")
        .items(&choices)
        .default(0)
        .interact()?;

    if selected == choices.len() - 1 {
        return Ok(());
    }

    let email = &emails[selected];

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Send {email} to the enabled breach-check providers?"
        ))
        .default(false)
        .interact()?
    {
        return Ok(());
    }

    println!("\n{GREY}Scanning providers...{RESET}");

    let scan = scan_email(email)?;
    scan_results_menu(&scan)
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("CIphera/1.3 breach-checker")
        .build()
        .context("Could not create HTTPS client")
}

fn scan_email(email: &str) -> Result<BreachScanResult> {
    let client = http_client()?;
    let mut providers = Vec::new();
    let mut normalized = Vec::new();

    providers.push(scan_xposedornot(&client, email, &mut normalized));
    providers.push(scan_leakcheck(&client, email, &mut normalized));
    providers.push(scan_hibp(&client, email, &mut normalized));
    providers.push(ProviderScan {
        provider: "Mozilla Monitor".into(),
        status: "manual-only".into(),
        findings: 0,
        note: "Mozilla Monitor does not expose a public automated email-lookup API for this integration; CIphera does not scrape its website.".into(),
        raw: json!({
            "provider": "Mozilla Monitor",
            "automated_lookup": false,
            "reason": "No supported public email lookup API used by CIphera"
        }),
    });

    dedupe_normalized_breaches(&mut normalized);

    Ok(BreachScanResult {
        email: email.to_string(),
        scanned_at: Utc::now().to_rfc3339(),
        providers,
        normalized_breaches: normalized,
    })
}

fn scan_xposedornot(client: &Client, email: &str, normalized: &mut Vec<Value>) -> ProviderScan {
    let response = client
        .get("https://api.xposedornot.com/v1/breach-analytics")
        .query(&[("email", email)])
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            let value: Value = resp.json().unwrap_or_else(|_| json!({"parse_error": true}));

            let details = value
                .pointer("/ExposedBreaches/breaches_details")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            for item in &details {
                normalized.push(json!({
                    "name": item.get("breach").and_then(Value::as_str).unwrap_or("Unknown"),
                    "domain": item.get("domain").and_then(Value::as_str).unwrap_or(""),
                    "date": item.get("xposed_date").and_then(Value::as_str).unwrap_or(""),
                    "data_exposed": item.get("xposed_data").and_then(Value::as_str).unwrap_or(""),
                    "description": item.get("details").and_then(Value::as_str).unwrap_or(""),
                    "verified": item.get("verified").and_then(Value::as_str).unwrap_or(""),
                    "sources": ["XposedOrNot"]
                }));
            }

            ProviderScan {
                provider: "XposedOrNot".into(),
                status: if status.is_success() {
                    "ok"
                } else {
                    status.as_str()
                }
                .into(),
                findings: details.len(),
                note: "Free public API; detailed breach analytics.".into(),
                raw: value,
            }
        }
        Err(err) => ProviderScan {
            provider: "XposedOrNot".into(),
            status: "error".into(),
            findings: 0,
            note: err.to_string(),
            raw: json!({"error": err.to_string()}),
        },
    }
}

fn scan_leakcheck(client: &Client, email: &str, normalized: &mut Vec<Value>) -> ProviderScan {
    let response = client
        .get("https://leakcheck.io/api/public")
        .query(&[("check", email)])
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            let value: Value = resp.json().unwrap_or_else(|_| json!({"parse_error": true}));

            let mut count = 0usize;

            if let Some(sources) = value.get("sources").and_then(Value::as_array) {
                count = sources.len();

                for source in sources {
                    let name = source
                        .get("name")
                        .or_else(|| source.get("source"))
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown");

                    let date = source.get("date").and_then(Value::as_str).unwrap_or("");

                    let data = source
                        .get("data")
                        .or_else(|| source.get("fields"))
                        .cloned()
                        .unwrap_or(Value::Null);

                    normalized.push(json!({
                        "name": name,
                        "date": date,
                        "data_exposed": data,
                        "sources": ["LeakCheck"]
                    }));
                }
            } else if let Some(arr) = value.as_array() {
                count = arr.len();
            }

            ProviderScan {
                provider: "LeakCheck Public".into(),
                status: if status.is_success() { "ok" } else { status.as_str() }.into(),
                findings: count,
                note: "Free public API; returns breach sources and exposed-data categories, not leaked secret values.".into(),
                raw: value,
            }
        }
        Err(err) => ProviderScan {
            provider: "LeakCheck Public".into(),
            status: "error".into(),
            findings: 0,
            note: err.to_string(),
            raw: json!({"error": err.to_string()}),
        },
    }
}

fn scan_hibp(client: &Client, email: &str, normalized: &mut Vec<Value>) -> ProviderScan {
    let key = match env::var("HIBP_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return ProviderScan {
                provider: "Have I Been Pwned".into(),
                status: "not-configured".into(),
                findings: 0,
                note: "Email lookup requires an HIBP API key. Set HIBP_API_KEY to enable it. HIBP's normal breached-account API is not a free unrestricted email API.".into(),
                raw: json!({"configured": false}),
            }
        }
    };

    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedAccount/{}",
        percent_encode_path(email)
    );

    let response = client
        .get(url)
        .header("hibp-api-key", key)
        .query(&[("truncateResponse", "false")])
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();

            if status.as_u16() == 404 {
                return ProviderScan {
                    provider: "Have I Been Pwned".into(),
                    status: "ok".into(),
                    findings: 0,
                    note: "No breaches returned for this address.".into(),
                    raw: json!([]),
                };
            }

            let value: Value = resp.json().unwrap_or_else(|_| json!({"parse_error": true}));
            let arr = value.as_array().cloned().unwrap_or_default();

            for item in &arr {
                let name = item
                    .get("Name")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown");
                let date = item.get("BreachDate").and_then(Value::as_str).unwrap_or("");
                let domain = item.get("Domain").and_then(Value::as_str).unwrap_or("");
                let data = item.get("DataClasses").cloned().unwrap_or(Value::Null);

                normalized.push(json!({
                    "name": name,
                    "domain": domain,
                    "date": date,
                    "data_exposed": data,
                    "sources": ["Have I Been Pwned"]
                }));
            }

            ProviderScan {
                provider: "Have I Been Pwned".into(),
                status: if status.is_success() {
                    "ok"
                } else {
                    status.as_str()
                }
                .into(),
                findings: arr.len(),
                note: "Configured through HIBP_API_KEY.".into(),
                raw: value,
            }
        }
        Err(err) => ProviderScan {
            provider: "Have I Been Pwned".into(),
            status: "error".into(),
            findings: 0,
            note: err.to_string(),
            raw: json!({"error": err.to_string()}),
        },
    }
}

fn percent_encode_path(input: &str) -> String {
    input
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn dedupe_normalized_breaches(items: &mut Vec<Value>) {
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();

    for item in items.drain(..) {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_lowercase();

        if let Some(existing) = merged.get_mut(&name) {
            let mut sources: HashSet<String> = HashSet::new();

            for node in [existing.get("sources"), item.get("sources")]
                .into_iter()
                .flatten()
            {
                if let Some(arr) = node.as_array() {
                    for source in arr {
                        if let Some(s) = source.as_str() {
                            sources.insert(s.to_string());
                        }
                    }
                }
            }

            existing["sources"] = Value::Array(sources.into_iter().map(Value::String).collect());

            if existing
                .get("data_exposed")
                .map(|v| v.is_null())
                .unwrap_or(true)
            {
                existing["data_exposed"] = item.get("data_exposed").cloned().unwrap_or(Value::Null);
            }
        } else {
            merged.insert(name, item);
        }
    }

    *items = merged.into_values().collect();
}

fn scan_results_menu(scan: &BreachScanResult) -> Result<()> {
    loop {
        clear_screen();
        println!(
            "{BLUE_DIM}╭─ BREACH SCAN RESULT ────────────────────────────────────────────╮{RESET}"
        );
        println!("{BLUE_DIM}│{RESET} Email:   {}", scan.email);
        println!("{BLUE_DIM}│{RESET} Scanned: {}", scan.scanned_at);
        println!(
            "{BLUE_DIM}│{RESET} Unique normalized breaches: {}",
            scan.normalized_breaches.len()
        );
        println!("{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}\n");

        for provider in &scan.providers {
            let colour = if provider.status == "ok" {
                GREEN
            } else if provider.status == "error" {
                RED
            } else {
                YELLOW
            };
            println!(
                "{}●{RESET} {:<24} {:<16} {} findings",
                colour, provider.provider, provider.status, provider.findings
            );
        }

        println!();

        let options = [
            "View breach tree",
            "View normalized JSON",
            "View provider raw JSON",
            "Back",
        ];

        match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Result view")
            .items(&options)
            .default(0)
            .interact()?
        {
            0 => {
                print_breach_tree(scan);
                pause();
            }
            1 => {
                print_json(&json!({
                    "email": scan.email,
                    "scanned_at": scan.scanned_at,
                    "breaches": scan.normalized_breaches,
                }))?;
                pause();
            }
            2 => raw_provider_json_menu(scan)?,
            3 => return Ok(()),
            _ => {}
        }
    }
}

fn print_breach_tree(scan: &BreachScanResult) {
    clear_screen();
    println!("{BLUE}{}{RESET}", scan.email);

    if scan.normalized_breaches.is_empty() {
        println!("└── {GREEN}No normalized breach records returned by enabled providers.{RESET}");
        return;
    }

    for (index, breach) in scan.normalized_breaches.iter().enumerate() {
        let last = index + 1 == scan.normalized_breaches.len();
        let branch = if last { "└──" } else { "├──" };
        let child = if last { "   " } else { "│  " };

        let name = breach
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        println!("{branch} {YELLOW}{name}{RESET}");

        if let Some(domain) = breach.get("domain").and_then(Value::as_str) {
            if !domain.is_empty() {
                println!("{child}├── Domain: {domain}");
            }
        }

        if let Some(date) = breach.get("date").and_then(Value::as_str) {
            if !date.is_empty() {
                println!("{child}├── Date: {date}");
            }
        }

        if let Some(data) = breach.get("data_exposed") {
            if !data.is_null() {
                println!("{child}├── Data exposed: {}", json_inline(data));
            }
        }

        if let Some(sources) = breach.get("sources") {
            println!("{child}└── Sources: {}", json_inline(sources));
        }
    }
}

fn json_inline(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "?".into()),
    }
}

fn raw_provider_json_menu(scan: &BreachScanResult) -> Result<()> {
    let mut labels: Vec<String> = scan.providers.iter().map(|p| p.provider.clone()).collect();

    labels.push("← Back".into());

    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Provider")
        .items(&labels)
        .default(0)
        .interact()?;

    if choice == labels.len() - 1 {
        return Ok(());
    }

    print_json(&scan.providers[choice].raw)?;
    pause();
    Ok(())
}

fn print_json(value: &Value) -> Result<()> {
    clear_screen();
    println!(
        "{BLUE_DIM}╭─ JSON ───────────────────────────────────────────────────────────╮{RESET}"
    );
    println!("{}", serde_json::to_string_pretty(value)?);
    println!(
        "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}"
    );
    Ok(())
}

fn backups_menu(
    vault: &mut Vault,
    vault_path: &Path,
    master: &str,
    security: &SecurityProfile,
) -> Result<()> {
    loop {
        clear_screen();
        let options = [
            "Create encrypted backup",
            "Restore encrypted backup",
            "Back",
        ];

        match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Backups")
            .items(&options)
            .default(0)
            .interact()?
        {
            0 => {
                let dest = backup_vault(vault_path)?;
                success(&format!("Encrypted backup created\n{}", dest.display()));
            }
            1 => {
                let backups = list_backups(vault_path)?;
                if backups.is_empty() {
                    warning_box("No CIphera backups were found.");
                    pause();
                    continue;
                }

                let labels: Vec<String> = backups
                    .iter()
                    .map(|p| {
                        p.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string()
                    })
                    .collect();

                let selected = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Backup to restore")
                    .items(&labels)
                    .default(0)
                    .interact()?;

                let backup = &backups[selected];

                warning_box("Restoring replaces the current encrypted vault.\nCIphera will create a safety backup first.");

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(format!("Restore {}?", backup.display()))
                    .default(false)
                    .interact()?
                {
                    let _safety = backup_vault(vault_path)?;
                    let raw = fs::read(backup)?;
                    fs::write(vault_path, raw)?;
                    fs::set_permissions(vault_path, fs::Permissions::from_mode(0o600))?;

                    match load_vault(vault_path, master) {
                        Ok((restored, _, restored_security)) => {
                            *vault = restored;

                            if restored_security.keyfile_required != security.keyfile_required {
                                warning_box("Backup restored, but its keyfile settings differ from this session. Restart CIphera before making further changes.");
                                pause();
                                return Ok(());
                            }

                            success("Encrypted backup restored. Restart CIphera is recommended.");
                        }
                        Err(err) => {
                            error_box(&format!("Restore validation failed: {err}"));
                            pause();
                        }
                    }
                }
            }
            2 => return Ok(()),
            _ => {}
        }
    }
}

fn backup_vault(vault_path: &Path) -> Result<PathBuf> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid vault path"))?;
    let backup_dir = parent.join("backups");

    fs::create_dir_all(&backup_dir)?;
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700))?;

    let dest = backup_dir.join(format!(
        "vault-{}.ciphera",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));

    fs::copy(vault_path, &dest)?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    Ok(dest)
}

fn list_backups(vault_path: &Path) -> Result<Vec<PathBuf>> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid vault path"))?;
    let backup_dir = parent.join("backups");

    if !backup_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("ciphera"))
        .collect();

    entries.sort();
    entries.reverse();
    Ok(entries)
}

fn security_menu(
    vault: &Vault,
    vault_path: &Path,
    salt: &[u8],
    master: &str,
    security: &mut SecurityProfile,
) -> Result<()> {
    loop {
        clear_screen();

        println!(
            "{BLUE_DIM}╭─ SECURITY ──────────────────────────────────────────────────────╮{RESET}"
        );
        println!("{BLUE_DIM}│{RESET} Encryption       XChaCha20-Poly1305");
        println!("{BLUE_DIM}│{RESET} Key derivation   Argon2id");
        println!(
            "{BLUE_DIM}│{RESET} KDF memory       {} MiB",
            security.memory_kib / 1024
        );
        println!(
            "{BLUE_DIM}│{RESET} KDF iterations   {}",
            security.iterations
        );
        println!("{BLUE_DIM}│{RESET} KDF lanes        {}", security.lanes);
        println!(
            "{BLUE_DIM}│{RESET} Keyfile          {}",
            if security.keyfile_required {
                "required"
            } else {
                "disabled"
            }
        );
        println!(
            "{BLUE_DIM}│{RESET} Session timeout  {} min",
            security.auto_lock_minutes
        );
        println!("{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}\n");

        let options = [
            "Benchmark & tune Argon2id",
            "Enable / rotate keyfile",
            "Disable keyfile",
            "Set session timeout",
            "Vault integrity + permissions check",
            "Security notes",
            "Back",
        ];

        match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Security")
            .items(&options)
            .default(0)
            .interact()?
        {
            0 => {
                let recommended = benchmark_argon2(master, salt)?;
                println!(
                    "\n{GREEN}Recommended:{RESET} {} MiB / {} iterations / {} lane",
                    recommended.memory_kib / 1024,
                    recommended.iterations,
                    recommended.lanes
                );

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Apply these parameters and re-encrypt the vault?")
                    .default(true)
                    .interact()?
                {
                    let _backup = backup_vault(vault_path)?;
                    security.memory_kib = recommended.memory_kib;
                    security.iterations = recommended.iterations;
                    security.lanes = recommended.lanes;
                    save_vault(vault_path, master, salt, security, vault)?;
                    success("Argon2id parameters upgraded. A backup was created first.");
                }
            }
            1 => {
                let path = resolve_keyfile_path()?;

                warning_box(&format!(
                    "CIphera will generate a random 256-bit keyfile.\n\
                     The vault will require BOTH your master password and this file.\n\
                     Default keyfile: {}\n\
                     For strongest protection, move a copy to removable media and set CIPHERA_KEYFILE.",
                    path.display()
                ));

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Generate/rotate the CIphera keyfile?")
                    .default(false)
                    .interact()?
                {
                    let _backup = backup_vault(vault_path)?;

                    let old_required = security.keyfile_required;
                    let old_keyfile_backup = if old_required && path.exists() {
                        let backup_path = path.with_extension(format!(
                            "key.backup-{}",
                            Utc::now().format("%Y%m%d-%H%M%S")
                        ));
                        fs::copy(&path, &backup_path)?;
                        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
                        Some(backup_path)
                    } else {
                        None
                    };

                    generate_keyfile(&path)?;
                    security.keyfile_required = true;

                    if let Err(err) = save_vault(vault_path, master, salt, security, vault) {
                        security.keyfile_required = old_required;

                        if let Some(old_path) = &old_keyfile_backup {
                            let _ = fs::copy(old_path, &path);
                            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                        }

                        return Err(err);
                    }

                    let backup_note = old_keyfile_backup
                        .as_ref()
                        .map(|p| format!("\nPrevious keyfile backup: {}", p.display()))
                        .unwrap_or_default();

                    success(&format!(
                        "Keyfile enabled.\n{}\nKeep an offline backup of this file.{}",
                        path.display(),
                        backup_note
                    ));
                }
            }
            2 => {
                if !security.keyfile_required {
                    warning_box("Keyfile protection is already disabled.");
                    pause();
                    continue;
                }

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(
                        "Disable keyfile protection and re-encrypt using the master password only?",
                    )
                    .default(false)
                    .interact()?
                {
                    let _backup = backup_vault(vault_path)?;
                    security.keyfile_required = false;
                    save_vault(vault_path, master, salt, security, vault)?;
                    success("Keyfile requirement disabled. Existing keyfile was not deleted.");
                }
            }
            3 => {
                let minutes: u64 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Lock timeout in minutes (0 disables)")
                    .default(security.auto_lock_minutes)
                    .interact_text()?;

                security.auto_lock_minutes = minutes.min(240);
                save_vault(vault_path, master, salt, security, vault)?;
                success("Session timeout preference saved.");
            }
            4 => {
                integrity_check(vault_path, master)?;
                pause();
            }
            5 => {
                clear_screen();
                println!("{BLUE_DIM}╭─ SECURITY NOTES ─────────────────────────────────────────────────╮{RESET}");
                println!(
                    "{BLUE_DIM}│{RESET} • Vault plaintext is never intentionally written to disk."
                );
                println!("{BLUE_DIM}│{RESET} • A fresh 192-bit XChaCha nonce is generated on every save.");
                println!("{BLUE_DIM}│{RESET} • Decrypted JSON/key buffers are zeroized after use where practical.");
                println!("{BLUE_DIM}│{RESET} • Vault and backup files are forced to user-only permissions.");
                println!("{BLUE_DIM}│{RESET} • A keyfile protects a copied vault only if the attacker does not also get the keyfile.");
                println!("{BLUE_DIM}│{RESET} • Malware/root access while the vault is unlocked can still capture secrets.");
                println!(
                    "{BLUE_DIM}│{RESET} • TPM/FIDO2 hardware binding is not enabled in this build."
                );
                println!("{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}");
                pause();
            }
            6 => return Ok(()),
            _ => {}
        }
    }
}

fn benchmark_argon2(master: &str, salt: &[u8]) -> Result<SecurityProfile> {
    println!("\n{GREY}Benchmarking Argon2id on this machine...{RESET}");

    let base = SecurityProfile {
        memory_kib: 64 * 1024,
        iterations: 3,
        lanes: 1,
        keyfile_required: false,
        auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
    };

    let start = Instant::now();
    let mut key = derive_key(master, salt, &base)?;
    key.zeroize();
    let elapsed = start.elapsed();

    let (memory_kib, iterations) = if elapsed < Duration::from_millis(250) {
        (256 * 1024, 4)
    } else if elapsed < Duration::from_millis(500) {
        (128 * 1024, 4)
    } else {
        (64 * 1024, 3)
    };

    println!(
        "{GREY}Baseline 64 MiB / 3 iterations: {} ms{RESET}",
        elapsed.as_millis()
    );

    Ok(SecurityProfile {
        memory_kib,
        iterations,
        lanes: 1,
        keyfile_required: false,
        auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
    })
}

fn generate_keyfile(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    bytes.zeroize();

    Ok(())
}

fn integrity_check(vault_path: &Path, master: &str) -> Result<()> {
    clear_screen();
    println!(
        "{BLUE_DIM}╭─ VAULT INTEGRITY ───────────────────────────────────────────────╮{RESET}"
    );

    let metadata = fs::metadata(vault_path)?;
    let mode = metadata.mode() & 0o777;

    println!(
        "{BLUE_DIM}│{RESET} File permissions: {:o} {}",
        mode,
        if mode == 0o600 { "✓" } else { "!" }
    );
    println!("{BLUE_DIM}│{RESET} Owner UID: {}", metadata.uid());

    let envelope = read_envelope(vault_path)?;

    println!("{BLUE_DIM}│{RESET} Format version: {}", envelope.version);
    println!(
        "{BLUE_DIM}│{RESET} Argon2id memory: {} MiB",
        envelope.kdf_memory_kib / 1024
    );
    println!(
        "{BLUE_DIM}│{RESET} Argon2id iterations: {}",
        envelope.kdf_iterations
    );
    println!(
        "{BLUE_DIM}│{RESET} Keyfile required: {}",
        envelope.keyfile_required
    );

    match load_vault(vault_path, master) {
        Ok((vault, _, _)) => {
            println!("{BLUE_DIM}│{RESET} AEAD authentication/decryption: {GREEN}PASS{RESET}");
            println!(
                "{BLUE_DIM}│{RESET} Decrypted entry count: {}",
                vault.entries.len()
            );
        }
        Err(err) => {
            println!("{BLUE_DIM}│{RESET} AEAD authentication/decryption: {RED}FAIL{RESET}");
            println!("{BLUE_DIM}│{RESET} Error: {err}");
        }
    }

    println!(
        "{BLUE_DIM}╰─────────────────────────────────────────────────────────────────╯{RESET}"
    );
    Ok(())
}

fn parse_tags(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.to_lowercase()))
        .map(ToString::to_string)
        .collect()
}

fn empty(value: &str) -> &str {
    if value.trim().is_empty() {
        "—"
    } else {
        value
    }
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(anyhow!("Selected field is empty"));
    }

    if env::var_os("WAYLAND_DISPLAY").is_some() && command_exists("wl-copy") {
        pipe_to_command("wl-copy", &[], text)?;
        spawn_clipboard_clear("wl-copy");
        return Ok(());
    }

    if command_exists("xclip") {
        pipe_to_command("xclip", &["-selection", "clipboard"], text)?;
        spawn_clipboard_clear("xclip");
        return Ok(());
    }

    Err(anyhow!("Install wl-clipboard on Wayland or xclip on X11"))
}

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn pipe_to_command(program: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not start {program}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(text.as_bytes())?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("{program} failed"));
    }

    Ok(())
}

fn spawn_clipboard_clear(program: &str) {
    let command = if program == "wl-copy" {
        format!("sleep {CLIPBOARD_CLEAR_SECONDS}; printf '' | wl-copy")
    } else {
        format!("sleep {CLIPBOARD_CLEAR_SECONDS}; printf '' | xclip -selection clipboard")
    };

    let _ = Command::new("sh")
        .args(["-c", &command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let password = generate_password(32, true);
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn tags_are_trimmed_and_deduplicated_case_insensitively() {
        let tags = parse_tags("work, Work, email,  gaming ");
        assert_eq!(tags, vec!["work", "email", "gaming"]);
    }

    #[test]
    fn percent_encoding_handles_email_symbols() {
        assert_eq!(
            percent_encode_path("user+test@example.com"),
            "user%2Btest%40example.com"
        );
    }

    #[test]
    fn new_security_profile_uses_hardened_defaults() {
        let profile = SecurityProfile::default();
        assert_eq!(profile.memory_kib, 128 * 1024);
        assert_eq!(profile.iterations, 4);
        assert_eq!(profile.lanes, 1);
        assert!(!profile.keyfile_required);
    }
}
