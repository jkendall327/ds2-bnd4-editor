use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use cbc::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor, Encryptor,
};
use clap::{Parser, Subcommand};
use md5::{Digest, Md5};
use std::{fs, path::PathBuf};

const DS2_KEY: [u8; 16] = [
    0x59, 0x9f, 0x9b, 0x69, 0x96, 0x40, 0xa5, 0x52, 0x36, 0xee, 0x2d, 0x70, 0x83, 0x5e, 0xc7, 0x44,
];

const BND4_MAGIC: &[u8; 4] = b"BND4";
const BND4_HEADER_LEN: usize = 64;
const BND4_ENTRY_HEADER_LEN: usize = 32;
const ENTRY_MAGIC: [u8; 8] = [0x50, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];

/// Python: hex_pattern1_Fixed = "0A 00 00 00 6C 00 00 00 BC 00 01"
/// We'll search for exactly these 11 bytes in USERDATA.
const ANCHOR_PATTERN: &[u8] = &[
    0x0A, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0xBC, 0x00, 0x01,
];

/// Python: ng_distance = -6664 (relative to anchor)
const NG_DISTANCE: isize = -6664;

#[derive(Parser)]
#[command(
    version,
    about = "Dark Souls II SL2 (PC) decrypt/edit/repack (NG only)"
)]
struct Cli {
    /// Input .sl2 file
    input: PathBuf,

    /// Output .sl2 path (required for set-ng)
    #[arg(long)]
    output: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show entry list (index + name) and NG value if found
    Show,
    /// Set NG value for a given entry index (0-based BND4 entry that contains USERDATA)
    SetNg {
        /// Entry index (as reported by `show`)
        entry: usize,
        /// New NG value (u32)
        value: u32,
    },
}

#[derive(Clone)]
struct EntryMeta {
    index: usize,
    size_total: usize,  // header[8..12]
    data_offset: usize, // header[16..20]
    name_offset: usize, // header[20..24]
    footer_len: usize,  // header[24..28]
}

#[derive(Clone)]
struct DecryptedEntry {
    meta: EntryMeta,
    name: String,
    iv: [u8; 16],
    /// Raw encrypted BLOCK (without the 16-byte checksum), as in file.
    encrypted: Vec<u8>,
    /// Decrypted payload after trimming (skip 20 bytes; cut to embedded length).
    plaintext: Vec<u8>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut sl2 = fs::read(&cli.input).with_context(|| "Failed to read input .sl2")?;
    ensure_bnd4(&sl2)?;

    match cli.cmd {
        Command::Show => {
            let entries = decrypt_all(&sl2)?;
            for e in &entries {
                // NG probe (optional)
                let ng = find_ng(&e.plaintext).map(|(_, v)| v);
                match ng {
                    Some(v) => println!("#{:<2} {:<16} NG={}", e.meta.index, e.name, v),
                    None => println!("#{:<2} {:<16} NG=<n/a>", e.meta.index, e.name),
                }
            }
        }
        Command::SetNg { entry, value } => {
            let output = cli
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("--output is required for set-ng"))?;
            let mut entries = decrypt_all(&sl2)?;

            let e = entries
                .iter_mut()
                .find(|e| e.meta.index == entry)
                .ok_or_else(|| anyhow!("Entry index {} not found", entry))?;

            // Mutate in-place
            set_ng(&mut e.plaintext, value)?;

            // Re-encrypt this entry back into the sl2 buffer (checksum + ciphertext).
            reencrypt_entry_into(&mut sl2, e)?;

            // Write output
            fs::write(output, &sl2).with_context(|| "Failed to write output .sl2")?;
            println!("Wrote modified SL2 to {}", output.display());
        }
    }

    Ok(())
}

fn ensure_bnd4(buf: &[u8]) -> Result<()> {
    if buf.len() < BND4_HEADER_LEN || &buf[0..4] != BND4_MAGIC {
        bail!("Not a BND4/SL2 file");
    }
    Ok(())
}

fn read_num_entries(buf: &[u8]) -> Result<usize> {
    let n = LittleEndian::read_i32(&buf[12..16]);
    if n < 0 {
        bail!("Negative entry count");
    }
    Ok(n as usize)
}

fn read_entry_meta(buf: &[u8], index: usize) -> Option<EntryMeta> {
    let pos = BND4_HEADER_LEN + BND4_ENTRY_HEADER_LEN * index;
    if pos + BND4_ENTRY_HEADER_LEN > buf.len() {
        return None;
    }
    let hdr = &buf[pos..pos + BND4_ENTRY_HEADER_LEN];
    if hdr[0..8] != ENTRY_MAGIC {
        return None;
    }
    let size_total = LittleEndian::read_i32(&hdr[8..12]);
    let data_offset = LittleEndian::read_i32(&hdr[16..20]);
    let name_offset = LittleEndian::read_i32(&hdr[20..24]);
    let footer_len = LittleEndian::read_i32(&hdr[24..28]);

    if size_total <= 0 || data_offset <= 0 || name_offset <= 0 {
        return None;
    }

    Some(EntryMeta {
        index,
        size_total: size_total as usize,
        data_offset: data_offset as usize,
        name_offset: name_offset as usize,
        footer_len: footer_len.max(0) as usize,
    })
}

fn read_entry_name(buf: &[u8], name_offset: usize) -> String {
    if name_offset >= buf.len() {
        return format!("entry_??");
    }
    let mut s = &buf[name_offset..buf.len().min(name_offset + 24)];
    if let Some(z) = s.iter().position(|&b| b == 0) {
        s = &s[..z];
    }
    match std::str::from_utf8(s) {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => "entry".to_string(),
    }
}

fn decrypt_all(buf: &[u8]) -> Result<Vec<DecryptedEntry>> {
    ensure_bnd4(buf)?;
    let n = read_num_entries(buf)?;
    let mut out = Vec::new();

    for i in 0..n {
        let Some(meta) = read_entry_meta(buf, i) else {
            continue;
        };
        // bounds
        if meta.data_offset + meta.size_total > buf.len() || meta.name_offset >= buf.len() {
            continue;
        }

        let name = read_entry_name(buf, meta.name_offset);

        // Layout at data_offset:
        // [0..16) = MD5 checksum of ciphertext
        // [16..32) = IV
        // [16..size_total) = ciphertext
        if meta.size_total < 32 {
            continue;
        }
        let iv = &buf[meta.data_offset + 16..meta.data_offset + 32];
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(iv);

        let encrypted = &buf[meta.data_offset + 16..meta.data_offset + meta.size_total];
        let mut ct = encrypted.to_vec();

        // Decrypt (NoPadding; format embeds len)
        let dec = Decryptor::<Aes128>::new_from_slices(&DS2_KEY, &iv_arr)?;
        dec.decrypt_padded_mut::<NoPadding>(&mut ct)
            .map_err(|_| anyhow!("AES decrypt failed for entry {}", i))?;

        // Trim: first 16 bytes junk, next 4 bytes (LE i32) embedded length
        let plaintext = if ct.len() >= 20 {
            let em_len = LittleEndian::read_i32(&ct[16..20]);
            let start = 20usize;
            let mut end = start.saturating_add(em_len.max(0) as usize);
            if em_len < 0 || end > ct.len() {
                end = ct.len();
            }
            ct[start..end].to_vec()
        } else if ct.len() > 16 {
            ct[16..].to_vec()
        } else {
            Vec::new()
        };

        out.push(DecryptedEntry {
            meta,
            name,
            iv: iv_arr,
            encrypted: encrypted.to_vec(),
            plaintext,
        });
    }

    Ok(out)
}

/// Try to find the anchor pattern and return (ng_offset, ng_value).
fn find_ng(usr: &[u8]) -> Option<(usize, u32)> {
    let anchor = find_bytes(usr, ANCHOR_PATTERN)?;
    // NG offset = anchor + NG_DISTANCE
    let base = anchor as isize + NG_DISTANCE;
    if base < 0 || (base as usize) + 4 > usr.len() {
        return None;
    }
    let off = base as usize;
    let val = LittleEndian::read_u32(&usr[off..off + 4]);
    Some((off, val))
}

/// Set NG value in-place given the same anchor logic.
fn set_ng(usr: &mut [u8], new_value: u32) -> Result<()> {
    if let Some((off, _)) = find_ng(usr) {
        LittleEndian::write_u32(&mut usr[off..off + 4], new_value);
        Ok(())
    } else {
        bail!("Could not locate NG via anchor pattern");
    }
}

/// Re-encrypt a (possibly modified) entry back into the .sl2 buffer.
/// We keep the original header & layout, recompute the MD5, and pad so
/// that the *stored* entry size remains unchanged (like the Python logic).
fn reencrypt_entry_into(sl2: &mut [u8], e: &DecryptedEntry) -> Result<()> {
    let meta = &e.meta;

    // Reconstruct the pre-encryption buffer: [len_le i32] + plaintext + zero padding to 16B boundary
    let mut buf = Vec::with_capacity(4 + e.plaintext.len() + 16);
    let len_le = (e.plaintext.len() as i32).to_le_bytes();
    buf.extend_from_slice(&len_le);
    buf.extend_from_slice(&e.plaintext);

    // zero pad to block size (16)
    let rem = buf.len() % 16;
    if rem != 0 {
        buf.resize(buf.len() + (16 - rem), 0);
    }

    // Encrypt with original IV
    let mut ct = buf.clone();
    let ct_len = ct.len();
    let enc = Encryptor::<Aes128>::new_from_slices(&DS2_KEY, &e.iv)?;
    enc.encrypt_padded_mut::<NoPadding>(&mut ct, ct_len)
        .map_err(|_| anyhow!("AES encrypt failed"))?;

    // Compute MD5 of ciphertext
    let mut hasher = Md5::new();
    hasher.update(&ct);
    let checksum = hasher.finalize(); // 16 bytes

    // Compose "[checksum][ciphertext]" and fit it back into original slot,
    // padding/truncating to original size_total as needed.
    let mut data = Vec::with_capacity(16 + ct.len());
    data.extend_from_slice(&checksum[..]);
    data.extend_from_slice(&ct);

    let start = meta.data_offset;
    let end = start + meta.size_total;

    if data.len() == meta.size_total {
        sl2[start..end].copy_from_slice(&data);
    } else if data.len() < meta.size_total {
        // pad with zeros to match original size
        let mut padded = data;
        padded.resize(meta.size_total, 0);
        sl2[start..end].copy_from_slice(&padded);
    } else {
        // If larger than original, still write (and adjust header size).
        // Risky in general, but mirrors the Python “may cause issues” path.
        // Update the size field in the per-entry header.
        let new_size_total = data.len() as i32;
        let hdr_pos = BND4_HEADER_LEN + BND4_ENTRY_HEADER_LEN * meta.index;
        sl2[start..start + data.len()].copy_from_slice(&data);
        sl2[hdr_pos + 8..hdr_pos + 12].copy_from_slice(&new_size_total.to_le_bytes());
    }

    Ok(())
}

/// Naive forward search (good enough for our small anchor).
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
