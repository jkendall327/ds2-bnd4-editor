use aes::Aes128;
use anyhow::{Context, Result, anyhow, bail};
use byteorder::{ByteOrder, LittleEndian};
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding},
};

const DS2_KEY: [u8; 16] = [
    0x59, 0x9f, 0x9b, 0x69, 0x96, 0x40, 0xa5, 0x52, 0x36, 0xee, 0x2d, 0x70, 0x83, 0x5e, 0xc7, 0x44,
];

const BND4_MAGIC: &[u8; 4] = b"BND4";
const BND4_HEADER_LEN: usize = 64;
const BND4_ENTRY_HEADER_LEN: usize = 32;
const ENTRY_MAGIC: [u8; 8] = [0x50, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];

#[derive(Debug)]
pub struct DecryptedEntry {
    pub index: usize,
    pub name: String,
    pub decrypted: Vec<u8>,
    // You can expose offsets/sizes if useful for further processing.
}

pub fn decrypt_ds2_sl2(raw: &[u8]) -> Result<Vec<DecryptedEntry>> {
    // 1) Basic sanity checks
    if raw.len() < BND4_HEADER_LEN {
        bail!("File too small to be a BND4/SL2");
    }
    if &raw[0..4] != BND4_MAGIC {
        bail!("'BND4' header not found");
    }

    let num_entries = LittleEndian::read_i32(&raw[12..16]);
    if num_entries < 0 {
        bail!("Negative entry count");
    }
    let num_entries = num_entries as usize;

    // 2) Iterate entries
    let mut out = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let pos = BND4_HEADER_LEN + BND4_ENTRY_HEADER_LEN * i;
        if pos + BND4_ENTRY_HEADER_LEN > raw.len() {
            // Same choice as Python: stop early if headers run off the end.
            break;
        }
        let header = &raw[pos..pos + BND4_ENTRY_HEADER_LEN];

        // 2a) Verify expected entry magic
        if header[0..8] != ENTRY_MAGIC {
            // Mirror the Python behavior: skip unexpected entries, don’t fail hard.
            continue;
        }

        // 2b) Read fields
        let entry_size = LittleEndian::read_i32(&header[8..12]); // total bytes from data_offset incl. checksum
        let _unk = LittleEndian::read_i32(&header[12..16]); // not used
        let data_offset = LittleEndian::read_i32(&header[16..20]);
        let name_offset = LittleEndian::read_i32(&header[20..24]);
        let footer_len = LittleEndian::read_i32(&header[24..28]); // not used

        // 2c) Validate fields
        if entry_size <= 0 {
            continue;
        }
        if data_offset <= 0 {
            continue;
        }
        let entry_size = entry_size as usize;
        let data_offset = data_offset as usize;
        let name_offset = if name_offset > 0 {
            name_offset as usize
        } else {
            continue;
        };

        if data_offset + entry_size > raw.len() {
            continue;
        }
        if name_offset >= raw.len() {
            continue;
        }

        // 3) Extract name (up to 24 bytes, null-terminated, UTF-8; fall back on entry_i)
        let mut name_bytes = &raw[name_offset..raw.len().min(name_offset + 24)];
        if let Some(nul) = name_bytes.iter().position(|&b| b == 0) {
            name_bytes = &name_bytes[..nul];
        }
        let name = match std::str::from_utf8(name_bytes) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => format!("entry_{}", i),
        };

        // 4) Extract IV and ciphertext (skip 16-byte checksum prefix)
        if data_offset + 32 > raw.len() {
            continue;
        } // need checksum(16) + iv(16) at least
        let iv = &raw[data_offset + 16..data_offset + 32];
        let encrypted = &raw[data_offset + 16..data_offset + entry_size];

        // 5) AES-128-CBC decrypt with NoPadding; the format embeds its own length
        //    We must operate on a mutable buffer for the cbc API.
        let mut buf = encrypted.to_vec();
        // Decryptor<Aes128> implements BlockDecryptMut with NoPadding
        let dec = Decryptor::<Aes128>::new_from_slices(&DS2_KEY, iv).context("bad key/iv")?;
        // NoPadding is fine because we'll trim manually to the embedded length.
        dec.decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| anyhow!("AES decrypt failed"))?;

        // 6) Trim: decrypted[0..16] is junk; next 4 bytes (16..20) is little-endian length
        if buf.len() < 20 {
            // Mirror Python: if too short, try to salvage "after 16", else empty
            let payload = if buf.len() > 16 {
                buf[16..].to_vec()
            } else {
                Vec::new()
            };
            out.push(DecryptedEntry {
                index: i,
                name,
                decrypted: payload,
            });
            continue;
        }
        let embedded_len = LittleEndian::read_i32(&buf[16..20]);
        let payload_start = 20;
        let mut payload_end = payload_start.saturating_add(embedded_len.max(0) as usize);
        // Guard against nonsense lengths
        if embedded_len < 0 || payload_end > buf.len() {
            // fallback: use what’s available minus header
            payload_end = buf.len();
        }
        let decrypted = buf[payload_start..payload_end].to_vec();

        let _ = footer_len; // quiet unused warning; footer bytes are ignored like in Python
        out.push(DecryptedEntry {
            index: i,
            name,
            decrypted,
        });
    }

    Ok(out)
}

/// Optional: reproduce the slot occupancy scan from entry #0.
///
/// Returns a map of (slot_number 1..=10) -> character name.
/// Mirrors the Python offsets and UTF-16LE decoding approach.
pub fn ds2_get_slot_occupancy(
    first_entry_data: &[u8],
) -> Result<std::collections::BTreeMap<u32, String>> {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();

    if first_entry_data.len() < 1300 {
        return Ok(map);
    }

    for idx in 0..10 {
        let check_off = 892 + 496 * idx;
        let name_off = 1286 + 496 * idx;
        if check_off >= first_entry_data.len() || name_off + 28 > first_entry_data.len() {
            continue;
        }
        if first_entry_data[check_off] != 0 {
            let name_bytes = &first_entry_data[name_off..name_off + 28]; // 14 UTF-16 code units
            // truncate at first 0x0000
            let mut end = name_bytes.len();
            for chunk in name_bytes.chunks_exact(2) {
                if chunk[0] == 0 && chunk[1] == 0 {
                    break;
                }
                end = (chunk.as_ptr() as usize + 2) - (name_bytes.as_ptr() as usize);
            }
            let (cow, _, had_errors) =
                encoding_rs::UTF_16LE.decode_without_bom_handling(name_bytes[..end].into());
            let name = if had_errors {
                format!("Character_{}", idx + 1)
            } else {
                cow.trim().to_string()
            };
            map.insert((idx + 1) as u32, name);
        }
    }
    Ok(map)
}

// Example usage:
//
// let entries = decrypt_ds2_sl2(&sl2_bytes)?;
// if let Some(first) = entries.iter().find(|e| e.index == 0) {
//     let slots = ds2_get_slot_occupancy(&first.decrypted)?;
//     println!("{slots:#?}");
// }
