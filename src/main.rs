use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use std::fs;

mod bdn4;
mod cli;

const ANCHOR_PATTERN: &[u8] = &[
    0x0A, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0xBC, 0x00, 0x01,
];

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    let mut sl2 = fs::read(&cli.input).with_context(|| "Failed to read input .sl2")?;

    bdn4::ensure_bnd4(&sl2)?;

    let ds2_key = load_ds2_key()?; // <--- load from env

    match cli.cmd {
        cli::Command::Show => {
            let entries = bdn4::decrypt_all(&sl2, &ds2_key)?;

            for e in &entries {
                let ng = bdn4::find_ng(&e.plaintext, ANCHOR_PATTERN).map(|(_, v)| v);

                match ng {
                    Some(v) => println!("#{:<2} {:<16} NG={}", e.meta.index, e.name, v),
                    None => println!("#{:<2} {:<16} NG=<n/a>", e.meta.index, e.name),
                }
            }
        }
        cli::Command::SetNg { entry, value } => {
            let output = cli
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("--output is required for set-ng"))?;

            let mut entries = bdn4::decrypt_all(&sl2, &ds2_key)?;

            let e = entries
                .iter_mut()
                .find(|e| e.meta.index == entry)
                .ok_or_else(|| anyhow!("Entry index {entry} not found"))?;

            // Mutate in-place
            bdn4::set_ng(&mut e.plaintext, value, ANCHOR_PATTERN)?;

            // Re-encrypt this entry back into the sl2 buffer (checksum + ciphertext).
            bdn4::reencrypt_entry_into(&mut sl2, e, &ds2_key)?;

            // Write output
            fs::write(output, &sl2).with_context(|| "Failed to write output .sl2")?;

            println!("Wrote modified SL2 to {}", output.display());
        }
    }

    Ok(())
}

fn load_ds2_key() -> Result<[u8; 16]> {
    // Load .env if present (no error if missing)
    dotenvy::dotenv()?;

    // Prefer HEX; allow BASE64 fallback if you want it
    if let Ok(s) = std::env::var("DS2_KEY") {
        let bytes = hex::decode(s.trim())
            .with_context(|| "DS2_KEY must be hex (e.g., 32 hex chars for 16 bytes)")?;
        if bytes.len() != 16 {
            bail!(
                "DS2_KEY must decode to exactly 16 bytes, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    } else if let Ok(s) = std::env::var("DS2_KEY_BASE64") {
        let bytes = base64::decode(s.trim())
            .with_context(|| "DS2_KEY_BASE64 must be valid base64 for 16 bytes")?;
        if bytes.len() != 16 {
            bail!(
                "DS2_KEY_BASE64 must decode to exactly 16 bytes, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    } else {
        Err(anyhow!(
            "Missing DS2_KEY (hex) or DS2_KEY_BASE64 (base64) in environment"
        ))
    }
}
