//! Pure, host-testable parsing of the Solana **secp256r1** precompile
//! instruction, used to verify passkey (WebAuthn / P-256) possession on-chain.
//!
//! The program itself cannot run ECDSA-P256 cheaply, so — exactly like the
//! Ed25519/secp256k1 precompiles — the client attaches a
//! `Secp256r1SigVerify` instruction to the transaction and this program then
//! inspects the instructions sysvar to confirm the precompile verified the
//! expected credential over the expected message.
//!
//! This module parses the precompile's data layout for the common **embedded**
//! case (offsets reference the precompile instruction's own data, signalled by
//! an instruction index of `u16::MAX`).
use crate::constants::P256_PUBKEY_LEN;

/// Sentinel instruction index meaning "this same instruction".
const IX_INDEX_SELF: u16 = u16::MAX;
/// Byte length of one `SignatureOffsets` entry.
const OFFSETS_LEN: usize = 14;

/// A parsed, self-contained secp256r1 verification: the credential public key
/// and the message that was signed.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCredential<'a> {
    /// The 33-byte compressed P-256 public key that the precompile verified.
    pub pubkey: &'a [u8],
    /// The message bytes that were signed.
    pub message: &'a [u8],
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Extract the (pubkey, message) verified by an embedded single-signature
/// secp256r1 precompile instruction, or `None` if the layout is unsupported.
///
/// Layout: `[num_sigs u8][pad u8]` then `num_sigs` × `SignatureOffsets`:
/// `sig_off u16, sig_ix u16, pk_off u16, pk_ix u16, msg_off u16, msg_size u16,
/// msg_ix u16`. Only the first signature is returned; only self-referential
/// (`*_ix == u16::MAX`) offsets are supported here.
#[must_use]
pub fn extract_embedded(data: &[u8]) -> Option<VerifiedCredential<'_>> {
    let num_sigs = *data.first()?;
    if num_sigs == 0 {
        return None;
    }
    // Offsets block begins after the 2-byte header.
    let base = 2usize;
    let _sig_off = read_u16(data, base)?;
    let sig_ix = read_u16(data, base + 2)?;
    let pk_off = read_u16(data, base + 4)? as usize;
    let pk_ix = read_u16(data, base + 6)?;
    let msg_off = read_u16(data, base + 8)? as usize;
    let msg_size = read_u16(data, base + 10)? as usize;
    let msg_ix = read_u16(data, base + 12)?;

    // Only the embedded (self-referential) case is supported here.
    if sig_ix != IX_INDEX_SELF || pk_ix != IX_INDEX_SELF || msg_ix != IX_INDEX_SELF {
        return None;
    }
    // Guard the offsets block itself.
    if base + OFFSETS_LEN > data.len() {
        return None;
    }
    let pubkey = data.get(pk_off..pk_off + P256_PUBKEY_LEN)?;
    let message = data.get(msg_off..msg_off + msg_size)?;
    Some(VerifiedCredential { pubkey, message })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal embedded single-signature precompile blob.
    fn blob(pubkey: &[u8], message: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.push(1u8); // num_sigs
        d.push(0u8); // padding
                     // Reserve the 14-byte offsets block; fill after we know positions.
        let offsets_at = d.len();
        d.extend_from_slice(&[0u8; OFFSETS_LEN]);
        // signature (64 bytes) — position recorded but content irrelevant here.
        let sig_off = d.len() as u16;
        d.extend_from_slice(&[7u8; 64]);
        let pk_off = d.len() as u16;
        d.extend_from_slice(pubkey);
        let msg_off = d.len() as u16;
        d.extend_from_slice(message);

        let mut w = |i: usize, v: u16| {
            d[offsets_at + i..offsets_at + i + 2].copy_from_slice(&v.to_le_bytes())
        };
        w(0, sig_off);
        w(2, IX_INDEX_SELF);
        w(4, pk_off);
        w(6, IX_INDEX_SELF);
        w(8, msg_off);
        w(10, message.len() as u16);
        w(12, IX_INDEX_SELF);
        d
    }

    #[test]
    fn extracts_embedded_credential() {
        let pubkey = [0xABu8; P256_PUBKEY_LEN];
        let message = b"login-challenge-nonce";
        let data = blob(&pubkey, message);
        let vc = extract_embedded(&data).unwrap();
        assert_eq!(vc.pubkey, &pubkey);
        assert_eq!(vc.message, message);
    }

    #[test]
    fn rejects_empty_and_zero_sigs() {
        assert!(extract_embedded(&[]).is_none());
        assert!(extract_embedded(&[0, 0]).is_none());
    }

    #[test]
    fn rejects_cross_instruction_reference() {
        let mut data = blob(&[1u8; P256_PUBKEY_LEN], b"x");
        // Set pk_ix (offset base+6 == index 2+6 = 8) to a real instruction index.
        data[8..10].copy_from_slice(&0u16.to_le_bytes());
        assert!(extract_embedded(&data).is_none());
    }

    #[test]
    fn rejects_truncated_offsets() {
        assert!(extract_embedded(&[1, 0, 0, 0]).is_none());
    }
}
