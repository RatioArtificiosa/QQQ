// SPDX-License-Identifier: Apache-2.0

//! Pure compute, for the `cpu` workload: a prime sieve and a matrix multiply.
//!
//! # Why two workloads behind one route
//!
//! `§9.1` names the row "`cpu` — prime sieve / matrix multiply", so both are the
//! same benchmark and the same budget. They stress different parts of codegen —
//! the sieve is branch-heavy integer work over a byte array, the multiply is a
//! tight `f64` loop — and a runtime can be good at one and poor at the other. Both
//! are here so the row cannot be satisfied by whichever one happens to flatter us.
//!
//! # Why the sieve is a bitset
//!
//! A `Vec<bool>` would be one byte per candidate, so the sieve's cost would be
//! dominated by memory bandwidth rather than by the arithmetic the row is meant to
//! measure. The bitset keeps the working set 8× smaller, which makes `cpu` measure
//! compute. The bit-twiddling is the price, and it is tested directly.
//!
//! # Why the multiply is `f64` and not integer
//!
//! `§10.5` routes float arithmetic that must be *deterministic* through a
//! host-mediated interface — because IEEE-754 is only reproducible if the
//! operation order is. This function is deterministic in the sense that matters
//! here: it is a fixed sequence of `f64` multiply-adds with no reassociation
//! opportunity taken, so the same input yields bit-identical output on every
//! target. It is used as a *workload*, and its result is folded to a single
//! integer so no float reaches a response body.

/// Count the primes below `n` with a Sieve of Eratosthenes over a bitset.
///
/// `n` is caller-supplied and validated by the route before it arrives.
#[must_use]
pub fn count_primes(n: u32) -> u32 {
    if n < 3 {
        return 0;
    }
    let n = n as usize;

    // Odd numbers only: bit `i` represents `2*i + 1`, so the array covers `n`.
    let bits = n / 2 + 1;
    let words = bits / 32 + 1;
    let mut sieve = vec![0u32; words];

    // `set(i)` marks `2*i+1` composite. Index 0 (the value 1) is marked, because 1
    // is not prime and the odd-only encoding would otherwise call it one.
    // Mutating through the `&mut` parameter needs no `mut` on the binding.
    let set = |sieve: &mut Vec<u32>, i: usize| sieve[i / 32] |= 1u32 << (i % 32);
    set(&mut sieve, 0);

    // Trial divide up to sqrt(n). `p*p <= n` rather than `p <= sqrt(n)` avoids a
    // float and its rounding.
    let mut p = 3usize;
    while p * p < n {
        let idx = p / 2;
        if sieve[idx / 32] & (1u32 << (idx % 32)) == 0 {
            // Start at p*p and step by 2p, which stays on odd numbers.
            let mut m = p * p;
            while m < n {
                set(&mut sieve, m / 2);
                m += 2 * p;
            }
        }
        p += 2;
    }

    // 2, plus every unmarked odd index whose value is below `n`.
    let mut count = 1u32;
    let mut i = 1usize;
    while i < bits {
        let value = 2 * i + 1;
        if value >= n {
            break;
        }
        if sieve[i / 32] & (1u32 << (i % 32)) == 0 {
            count += 1;
        }
        i += 1;
    }
    count
}

/// Multiply two `n`×`n` matrices of a deterministic pseudo-random fill, and fold
/// the result to one integer.
///
/// The matrices are generated rather than passed in so the workload's cost is a
/// function of `n` alone — a benchmark whose payload arrives over the network would
/// measure the network.
#[must_use]
pub fn matmul_trace(n: u32) -> u64 {
    let n = n as usize;
    let a = fill(n);
    let b = fill(n);

    let mut trace = 0u64;
    // The trace only needs the diagonal of the product, which is `O(n^2)` rather
    // than the full `O(n^3)` — but the row is *matrix multiply*, so the full
    // product is computed and the diagonal read off it. Measuring the cheap
    // shortcut would not be measuring what §9.1 says this row measures.
    let mut c = vec![0.0f64; n * n];
    for i in 0..n {
        for k in 0..n {
            let aik = a[i * n + k];
            if aik == 0.0 {
                continue;
            }
            for j in 0..n {
                c[i * n + j] += aik * b[k * n + j];
            }
        }
    }
    for i in 0..n {
        // Folded to an integer so no float crosses the ABI, and scaled so the
        // fractional part is not discarded entirely.
        trace = trace.wrapping_add((c[i * n + i] * 1024.0) as u64);
    }
    trace
}

/// A deterministic `n`×`n` fill.
///
/// A fixed linear congruential sequence, **not** a random source: `§10.5` requires
/// a deterministic run to produce identical output, and a benchmark that used
/// randomness would produce a different trace every run for reasons unrelated to
/// the runtime.
fn fill(n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n * n);
    let mut state = 2_463_534_242u64;
    for _ in 0..n * n {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        // Values in [0, 1): the top 24 bits scaled down.
        out.push(((state >> 40) as f64) / 16_777_216.0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sieve_matches_the_published_prime_counts() {
        // The counts of primes below 10^k, which is the standard check for a sieve
        // and is independent of this implementation.
        assert_eq!(count_primes(10), 4); // 2,3,5,7
        assert_eq!(count_primes(100), 25);
        assert_eq!(count_primes(1_000), 168);
        assert_eq!(count_primes(10_000), 1_229);
        assert_eq!(count_primes(100_000), 9_592);
        assert_eq!(count_primes(1_000_000), 78_498);
    }

    #[test]
    fn the_sieve_handles_the_small_boundaries() {
        // `n < 2` has no primes. These are the cases an off-by-one in the
        // odd-only encoding gets wrong, and the empty input must not panic.
        assert_eq!(count_primes(0), 0);
        assert_eq!(count_primes(1), 0);
        assert_eq!(count_primes(2), 0, "2 is not below 2");
        assert_eq!(count_primes(3), 1, "2 is the only prime below 3");
        assert_eq!(count_primes(4), 2);
        assert_eq!(count_primes(5), 2);
        assert_eq!(count_primes(6), 3, "2, 3 and 5");
    }

    #[test]
    fn the_sieve_does_not_call_one_prime() {
        // The odd-only encoding represents 1 at index 0. If it is not marked, 1 is
        // counted, and every count above is wrong by one.
        let with_one = count_primes(3);
        assert_eq!(with_one, 1, "the only prime below 3 is 2, not 1 and 2");
    }

    #[test]
    fn the_sieve_handles_a_word_boundary_and_counts_strictly_below() {
        // 32 is the bitset's word size, so values around 2*32+1 exercise the
        // index-to-word arithmetic.
        assert_eq!(count_primes(65), 18); // 2,3,5,7,11,...,61

        // **Strictly below n**, which the first version of this test got wrong: 67
        // is prime, so `count_primes(67)` must *exclude* it and `count_primes(68)`
        // must include it. Both values verified against an independent sieve.
        assert_eq!(count_primes(67), 18, "67 is not below 67");
        assert_eq!(count_primes(68), 19, "68 is the first n to include 67");
    }

    #[test]
    fn the_matrix_fill_is_deterministic() {
        // §10.5: the same input must yield identical output. A benchmark whose
        // payload changed between runs could not be compared between commits.
        assert_eq!(fill(4), fill(4));
        assert_eq!(matmul_trace(4), matmul_trace(4));
        assert_eq!(matmul_trace(8), matmul_trace(8));
    }

    #[test]
    fn the_matrix_values_are_in_range() {
        // The fill must produce [0,1): a value of exactly 1.0 would mean the scale
        // is off by one bit, and values outside the range would make the multiply's
        // magnitude drift with n.
        for v in fill(20) {
            assert!((0.0..1.0).contains(&v), "fill produced {v}, outside [0,1)");
        }
    }

    #[test]
    fn the_matrix_trace_changes_with_size() {
        // The control: if the trace were constant, the determinism assertion above
        // would pass while the workload did nothing.
        assert_ne!(
            matmul_trace(4),
            matmul_trace(6),
            "the trace must depend on n, or the workload measures nothing"
        );
        assert_ne!(matmul_trace(2), 0);
    }

    #[test]
    fn the_matrix_handles_the_degenerate_sizes() {
        // n = 0 and n = 1 are the cases a `Vec` index gets wrong.
        assert_eq!(matmul_trace(0), 0);
        let one = matmul_trace(1);
        assert!(one > 0, "a 1x1 product is a single non-zero square");
    }
}
