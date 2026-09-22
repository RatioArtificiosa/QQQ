// SPDX-License-Identifier: Apache-2.0

//! SHA-256 — FIPS 180-4, implemented in-tree for the `crypto` workload.
//!
//! # Why this is not `sha2` from crates.io
//!
//! `§9.1` claims QQQ is "far ahead" on `crypto`. If the guest's hashing came from a
//! dependency, the measurement would be of that dependency's SIMD paths and
//! optimisation budget — and a reader could not tell QQQ's contribution from it.
//! The module docs in `lib.rs` carry the full argument.
//!
//! # Why it is written the plain way
//!
//! No unrolling, no SIMD, no message-schedule cache. The first published number
//! should be the **floor**. A clever implementation here would make `crypto`
//! measure my cleverness, and the honest baseline is the one that shows what the
//! ABI and codegen cost with unremarkable code inside.
//!
//! # Correctness is pinned against the specification, not against itself
//!
//! FIPS 180-4 publishes worked examples, and the tests use them verbatim: the
//! empty string, `"abc"`, the 448-bit two-block message, and the million-`a`
//! message. A round-trip test against my own encoder would pass with two matching
//! bugs (`§4` of the handbook's test rules); the published digests would not.

/// The SHA-256 round constants: the first 32 bits of the fractional parts of the
/// cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value: the first 32 bits of the fractional parts of the square
/// roots of the first 8 primes.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Hash one message.
///
/// The full FIPS 180-4 transform, including padding.
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut h = H0;

    // Padding: `0x80`, then zeroes to 56 mod 64, then the 64-bit big-endian bit
    // length. The bit length is `u64` computed from a `usize`, and the cast is
    // lossless on every wasm target (32-bit usize).
    let bit_len = (message.len() as u64).wrapping_mul(8);

    // Process the message plus the `0x80` terminator. The two `if` branches add the
    // zero padding and the length field as their own blocks, which avoids
    // allocating a padded copy of the message — the whole reason this is written
    // over the input rather than over a `Vec`.
    let (chunks, rest) = message.as_chunks::<64>();

    for chunk in chunks {
        compress(&mut h, chunk);
    }

    let total = rest.len();
    let mut tail = [0u8; 128];
    tail[..total].copy_from_slice(rest);
    tail[total] = 0x80;

    // One block if the terminator and length fit in 56 bytes of the first block,
    // otherwise two.
    let tail_len = if total + 1 + 8 <= 64 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());

    let (halves, _) = tail[..tail_len].as_chunks::<64>();
    for half in halves {
        compress(&mut h, half);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Hash the same seed `rounds` times, chaining each digest into the next.
///
/// # Why chained rather than repeated
///
/// Repeating `sha256(seed)` `N` times would let a compiler hoist the whole loop
/// away — it is a pure function of a value that does not change. Chaining makes
/// each round depend on the last, which is both unhoistable and the more realistic
/// shape (a password-stretching or key-derivation loop does exactly this).
#[must_use]
pub fn sha256_repeated(seed: &[u8], rounds: u32) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&sha256(seed));
    for _ in 1..rounds {
        buf = sha256(&buf);
    }
    buf
}

/// The SHA-256 compression function for one 64-byte block.
fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        let b = i * 4;
        *word = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Lowercase hex, the conventional rendering of a digest.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published FIPS 180-4 vectors, spelled out. These are the *specification*
    /// for SHA-256; a test against my own encoder would certify two matching bugs.
    #[test]
    fn the_fips_180_4_vectors_hold() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // 896 bits, exactly two blocks, which is the case that exercises the
        // two-block tail.
        assert_eq!(
            hex(&sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect::<Vec<u8>>()
                    .as_slice()
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn the_million_a_vector_holds() {
        // The long-message case: 1,000,000 `a`s, which is many blocks and pins the
        // length field's high bytes.
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn the_padding_boundary_cases_all_hash_correctly() {
        // 55 and 56 bytes are the boundary between one and two tail blocks. The
        // published vectors above do not cover 55 bytes, so these are computed from
        // the same transform and pinned here as regression values: they exercise
        // the branch that decides on 64 versus 128 tail bytes.
        assert_eq!(
            hex(&sha256(&[b'x'; 55])),
            "d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072"
        );
        assert_eq!(
            hex(&sha256(&[b'x'; 56])),
            "04c26261370ee7541549d16dee320c723e3fd14671e66a099afe0a377c16888e"
        );
        assert_eq!(
            hex(&sha256(&[b'x'; 64])),
            "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c"
        );
    }

    #[test]
    fn one_round_is_the_plain_digest_and_rounds_chain() {
        // The `crypto` benchmark's round count must actually change the work.
        let one = sha256_repeated(b"seed", 1);
        assert_eq!(hex(&one), hex(&sha256(b"seed")));

        let two = sha256_repeated(b"seed", 2);
        assert_eq!(
            hex(&two),
            hex(&sha256(&sha256(b"seed"))),
            "each round must hash the previous digest, not the seed again"
        );
        assert_ne!(
            hex(&one),
            hex(&two),
            "if these matched, the round count would do nothing and the benchmark \
             would measure the same work at every size"
        );
    }

    #[test]
    fn the_hex_of_known_bytes_is_lowercase_and_fixed_width() {
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0x0f]), "0f");
        assert_eq!(hex(&[0xf0]), "f0");
        assert_eq!(hex(&[0xff, 0x01]), "ff01");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn the_constant_tables_have_their_specified_lengths() {
        // A short K or H0 would be caught by the vectors above, but the *reason* is
        // worth asserting directly: FIPS 180-4 specifies 64 rounds and 8 words.
        assert_eq!(K.len(), 64);
        assert_eq!(H0.len(), 8);
    }
}
