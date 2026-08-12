//! Set operations and population estimates over [`Bloom001`] filters.
//!
//! A Bloom filter is a bit array, and the bit array of a union is the bitwise
//! OR of its inputs. That identity is what makes these operations worth having:
//! two filters built on separate machines, over disjoint shards of a key set,
//! merge into one filter over the whole set without either machine seeing the
//! other's keys.
//!
//! # Shape compatibility
//!
//! Bitwise operations are pointwise, so bit `i` of one filter must mean the
//! same thing as bit `i` of the other. That holds only when the two filters
//! agree on bit count, hash count, and seed, since those three determine which
//! bits a key sets. Combining mismatched filters would silently produce a
//! filter with false negatives, so [`Bloom001::union`] and
//! [`Bloom001::intersect`] check the shape first and return
//! [`Error::Incompatible`] rather than a broken filter.
//!
//! Two filters built with the same [`Params`](dmc_core::Params) are always
//! compatible, since sizing is a pure function of the parameters. Build both
//! sides with the same parameters and the check never fires.
//!
//! # Union is exact; intersection is not
//!
//! Union is sound in the strongest sense: a key in either input is found in the
//! result, and no key that was absent from both becomes more likely than the
//! result's own false positive rate.
//!
//! Intersection is weaker, and the difference is easy to miss. Every key in
//! both inputs is present in `a & b`, so there are still no false negatives.
//! But a bit survives the AND whenever *some* key of A set it and *some* key of
//! B set it — not necessarily the same key. So the result can contain bit
//! patterns that no single key ever produced, and its false positive rate runs
//! higher than either input's, sometimes far higher when the inputs are
//! densely filled. See [`Bloom001::intersect`] for the details and for what to
//! use instead when an exact intersection matters.
//!
//! # Estimating population
//!
//! After a union, [`len`](dmc_core::Filter::len) is no longer a useful count:
//! it reports how many keys were fed to the builder, and the union of two
//! 500-key filters over overlapping sets does not hold 1,000 distinct keys.
//! [`Bloom001::estimated_len`] recovers a count from the filter's own contents
//! instead, by inverting the fill ratio, so it stays meaningful after any of
//! these operations.

// Population and similarity estimates are statistical: bit counts and key
// counts convert to f64 for logarithms. MAX_BITS caps the array well below the
// 2^53 point where an f64 stops counting integers exactly.
#![allow(clippy::cast_precision_loss)]

use dmc_core::{Error, Result};

// Imported for the `[`Filter::...`]` doc links below rather than for code; the
// operations here take and return `Bloom001` directly.
#[allow(unused_imports)]
use dmc_core::Filter;

use crate::bloom_001::Bloom001;

impl Bloom001 {
    /// Returns a filter holding every key of `self` and every key of `other`.
    ///
    /// The bitwise OR of the two bit arrays. Exact: a key in either input is
    /// found in the result, with no false negatives introduced.
    ///
    /// The result's false positive rate is higher than either input's, because
    /// it holds more keys in the same number of bits. It is reported honestly
    /// by [`false_positive_rate`](Filter::false_positive_rate), which reads the
    /// filter's actual fill rather than assuming the requested rate still
    /// holds.
    ///
    /// [`len`](Filter::len) of the result is an estimate of the distinct key
    /// count, not the sum of the two inputs' lengths: the inputs may overlap,
    /// and the union of two 500-key filters over overlapping sets does not hold
    /// 1,000 keys. See [`estimated_len`](Bloom001::estimated_len) for how that
    /// number is derived and how far it can be trusted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incompatible`] if the two filters disagree on bit
    /// count, hash count, or seed. Filters built with the same
    /// [`Params`](dmc_core::Params) always agree on all three.
    ///
    /// # Examples
    ///
    /// Two shards merge into a filter over both:
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Filter, Params};
    ///
    /// // Same params on both sides, so the shapes match.
    /// let params = Params::new(100, 0.01);
    /// let west = Bloom001::build(&[b"alice", b"bob"], &params)?;
    /// let east = Bloom001::build(&[b"carol"], &params)?;
    ///
    /// let both = west.union(&east)?;
    ///
    /// assert!(both.contains(b"alice"));
    /// assert!(both.contains(b"carol"));
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    ///
    /// Mismatched shapes are refused rather than merged:
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Error, Params};
    ///
    /// let small = Bloom001::build(&[b"alice"], &Params::new(10, 0.01))?;
    /// let large = Bloom001::build(&[b"bob"], &Params::new(10_000, 0.01))?;
    ///
    /// assert!(matches!(
    ///     small.union(&large),
    ///     Err(Error::Incompatible { .. })
    /// ));
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn union(&self, other: &Self) -> Result<Self> {
        self.check_compatible(other)?;

        let mut merged = self.clone();
        for (word, incoming) in merged.words_mut().iter_mut().zip(other.words()) {
            *word |= incoming;
        }

        merged.set_len(merged.estimated_len());
        Ok(merged)
    }

    /// Returns a filter holding the keys present in both `self` and `other`.
    ///
    /// The bitwise AND of the two bit arrays. Every key in both inputs is found
    /// in the result, so this introduces no false negatives.
    ///
    /// # This is not an exact intersection
    ///
    /// A bit survives the AND when some key of A set it and some key of B set
    /// it. Those need not be the same key. So the result can hold a bit pattern
    /// that no key in either set ever produced, and it reports `true` for keys
    /// that are in neither input.
    ///
    /// The effect is real, not theoretical: the result's false positive rate is
    /// bounded below by the product of the inputs' rates but runs well above it
    /// in practice, and grows with how densely the inputs are filled. Two
    /// filters loaded to their design capacity can intersect into something
    /// that answers `true` far more often than either input would.
    ///
    /// [`false_positive_rate`](Filter::false_positive_rate) reports the
    /// inflated figure rather than the analytic one, since it reads the result's
    /// actual fill. Check it after intersecting. When the exact intersection
    /// matters, intersect the key sets and build a filter from the result;
    /// this operation is for the case where the key sets are gone and an
    /// approximate answer is worth more than none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incompatible`] if the two filters disagree on bit
    /// count, hash count, or seed.
    ///
    /// # Examples
    ///
    /// A key in both inputs survives; a key in only one does not:
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Filter, Params};
    ///
    /// // Sized generously so the inputs stay sparse and the AND stays clean.
    /// let params = Params::new(10_000, 0.001);
    /// let a = Bloom001::build(&[b"shared", b"only-a"], &params)?;
    /// let b = Bloom001::build(&[b"shared", b"only-b"], &params)?;
    ///
    /// let common = a.intersect(&b)?;
    ///
    /// assert!(common.contains(b"shared"));
    /// assert!(!common.contains(b"only-a"));
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn intersect(&self, other: &Self) -> Result<Self> {
        self.check_compatible(other)?;

        let mut common = self.clone();
        for (word, incoming) in common.words_mut().iter_mut().zip(other.words()) {
            *word &= incoming;
        }

        common.set_len(common.estimated_len());
        Ok(common)
    }

    /// Estimates how many distinct keys this filter holds.
    ///
    /// Inverts the fill ratio: with `m` bits, `k` hash functions, and `X` bits
    /// set, the population is about `-(m/k) · ln(1 - X/m)`. This is the
    /// Swamidass–Baldi estimator, and unlike [`len`](Filter::len) it reads the
    /// filter's own contents, so it stays meaningful after a
    /// [`union`](Bloom001::union) or an [`intersect`](Bloom001::intersect)
    /// where the count of keys handed to the builder no longer describes what
    /// the filter holds.
    ///
    /// # Accuracy
    ///
    /// Good while the filter is not saturated, and degrades as it fills: at
    /// high fill the logarithm's argument approaches zero and small differences
    /// in bit count swing the estimate hard. A completely full filter returns
    /// [`usize::MAX`] rather than infinity, since every key would be reported
    /// present and no finite count describes that.
    ///
    /// The estimate counts *distinct* keys. A filter built from 1,000 keys of
    /// which 400 were repeats estimates about 600, while `len` reports 1,000.
    /// Neither is wrong; they answer different questions.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let keys: Vec<Vec<u8>> = (0..1_000)
    ///     .map(|i| format!("key-{i}").into_bytes())
    ///     .collect();
    /// let borrowed: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    ///
    /// let filter = Bloom001::build(&borrowed, &Params::new(1_000, 0.01))?;
    /// let estimate = filter.estimated_len();
    ///
    /// // Within a few percent of the true 1,000.
    /// assert!((900..=1_100).contains(&estimate), "estimated {estimate}");
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    ///
    /// Duplicates are counted once, which is where this parts ways with `len`:
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let filter = Bloom001::build(
    ///     &[b"same", b"same", b"same"],
    ///     &Params::new(100, 0.01),
    /// )?;
    ///
    /// assert_eq!(filter.len(), 3, "three keys were supplied");
    /// assert_eq!(filter.estimated_len(), 1, "but only one is distinct");
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub fn estimated_len(&self) -> usize {
        let set = self.count_set_bits();

        if set == 0 {
            return 0;
        }

        let m = self.bit_count() as f64;
        let k = f64::from(self.hash_count());
        let x = set as f64;

        // A saturated filter reports every key present, which no finite count
        // describes. Saturating rather than returning an infinity keeps the
        // return type honest and stops the cast below from being undefined.
        if x >= m {
            return usize::MAX;
        }

        // n ≈ -(m/k) · ln(1 - X/m)
        let estimate = -(m / k) * (1.0 - x / m).ln();

        if estimate.is_finite() && estimate > 0.0 {
            // Bounded by the branch above: `x < m` keeps the logarithm finite,
            // so this cannot saturate to an unintended value.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let rounded = estimate.round() as usize;
            rounded
        } else {
            0
        }
    }

    /// Estimates the Jaccard similarity between two filters, in `0.0..=1.0`.
    ///
    /// The ratio of the estimated size of the intersection to the estimated
    /// size of the union: `|A ∩ B| / |A ∪ B|`. Zero means the key sets appear
    /// disjoint, one that they appear identical.
    ///
    /// Both terms come from [`estimated_len`](Bloom001::estimated_len) applied
    /// to the corresponding bit array, so this inherits that estimator's
    /// accuracy and degrades the same way as the filters fill. The intersection
    /// term is the popcount of the bitwise AND, which as
    /// [`intersect`](Bloom001::intersect) explains overstates the true overlap;
    /// expect this figure to read high for densely filled filters.
    ///
    /// Two empty filters are defined as similarity `1.0`. They contain the same
    /// thing — nothing — and returning zero for a pair that agrees completely
    /// would be the more surprising answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incompatible`] if the two filters disagree on bit
    /// count, hash count, or seed.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let params = Params::new(1_000, 0.01);
    /// let a = Bloom001::build(&[b"x", b"y"], &params)?;
    /// let same = Bloom001::build(&[b"x", b"y"], &params)?;
    /// let other = Bloom001::build(&[b"p", b"q"], &params)?;
    ///
    /// assert_eq!(a.jaccard_similarity(&same)?, 1.0);
    /// assert_eq!(a.jaccard_similarity(&other)?, 0.0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn jaccard_similarity(&self, other: &Self) -> Result<f64> {
        self.check_compatible(other)?;

        let union = self.union(other)?.estimated_len();
        let intersection = self.intersect(other)?.estimated_len();

        // Two empty filters hold the same thing: nothing.
        if union == 0 {
            return Ok(1.0);
        }

        // The estimators are independent, so rounding can put the intersection
        // a hair above the union. Clamp rather than report a similarity above
        // one, which would be arithmetically explicable and still wrong.
        Ok((intersection as f64 / union as f64).clamp(0.0, 1.0))
    }

    /// Estimates what fraction of `self`'s keys also appear in `other`.
    ///
    /// The containment coefficient `|A ∩ B| / |A|`, which unlike
    /// [`jaccard_similarity`](Bloom001::jaccard_similarity) is asymmetric: a
    /// small set fully inside a large one is fully contained, while the reverse
    /// direction is not. Use this to ask "is A a subset of B?" and Jaccard to
    /// ask "are A and B the same set?".
    ///
    /// An empty `self` is defined as fully contained, at `1.0`: the empty set is
    /// a subset of everything.
    ///
    /// Inherits the accuracy and the overstated-overlap caveat described on
    /// [`intersect`](Bloom001::intersect).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incompatible`] if the two filters disagree on bit
    /// count, hash count, or seed.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let params = Params::new(1_000, 0.01);
    /// let small = Bloom001::build(&[b"a"], &params)?;
    /// let large = Bloom001::build(&[b"a", b"b", b"c", b"d"], &params)?;
    ///
    /// // Every key of `small` is in `large`, but not the reverse.
    /// assert_eq!(small.containment_in(&large)?, 1.0);
    /// assert!(large.containment_in(&small)? < 0.5);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn containment_in(&self, other: &Self) -> Result<f64> {
        self.check_compatible(other)?;

        let own = self.estimated_len();

        // The empty set is a subset of everything.
        if own == 0 {
            return Ok(1.0);
        }

        let shared = self.intersect(other)?.estimated_len();

        Ok((shared as f64 / own as f64).clamp(0.0, 1.0))
    }

    /// Returns whether `other` can be combined with `self`.
    ///
    /// True when the two agree on bit count, hash count, and seed, which are
    /// exactly the three that determine which bits a key sets. Filters built
    /// with the same [`Params`](dmc_core::Params) always agree.
    ///
    /// Callers that would rather branch than handle an error check this first;
    /// the operations check it themselves regardless, so skipping it is safe.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let params = Params::new(100, 0.01);
    /// let a = Bloom001::build(&[b"a"], &params)?;
    /// let b = Bloom001::build(&[b"b"], &params)?;
    /// let odd = Bloom001::build(&[b"c"], &Params::new(100, 0.01).with_seed(9))?;
    ///
    /// assert!(a.is_compatible_with(&b));
    /// assert!(!a.is_compatible_with(&odd), "a different seed moves every bit");
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.bit_count() == other.bit_count()
            && self.hash_count() == other.hash_count()
            && self.seed() == other.seed()
    }

    /// Returns the fraction of bits currently set, in `0.0..=1.0`.
    ///
    /// The filter's fill. Useful on its own as a saturation warning: a fill
    /// near 1.0 means the filter answers `true` for almost everything and its
    /// reported false positive rate, while accurate, is no longer useful.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let empty = Bloom001::build(&[], &Params::new(100, 0.01))?;
    /// assert_eq!(empty.fill_ratio(), 0.0);
    ///
    /// let loaded = Bloom001::build(&[b"a", b"b"], &Params::new(100, 0.01))?;
    /// assert!(loaded.fill_ratio() > 0.0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        if self.bit_count() == 0 {
            return 0.0;
        }

        self.count_set_bits() as f64 / self.bit_count() as f64
    }

    /// Reports the first shape mismatch that would make a bitwise op unsound.
    ///
    /// Checked in a fixed order so the error names one cause rather than
    /// whichever the compiler evaluated first, which keeps the message stable
    /// for a test to assert on.
    fn check_compatible(&self, other: &Self) -> Result<()> {
        if self.bit_count() != other.bit_count() {
            return Err(Error::Incompatible {
                aspect: "bit_count",
                left: self.bit_count().to_string(),
                right: other.bit_count().to_string(),
            });
        }

        if self.hash_count() != other.hash_count() {
            return Err(Error::Incompatible {
                aspect: "hash_count",
                left: self.hash_count().to_string(),
                right: other.hash_count().to_string(),
            });
        }

        if self.seed() != other.seed() {
            return Err(Error::Incompatible {
                aspect: "seed",
                left: self.seed().to_string(),
                right: other.seed().to_string(),
            });
        }

        Ok(())
    }

    /// Counts the set bits across the backing store.
    ///
    /// Bits past `bit_count` in the final word are never set — `probes` yields
    /// positions modulo `bit_count` — so this counts whole words without
    /// masking the tail.
    fn count_set_bits(&self) -> usize {
        self.words()
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_core::Params;

    /// Distinct keys, prefixed so two calls can produce disjoint sets.
    fn keys(prefix: &str, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("{prefix}-{i}").into_bytes())
            .collect()
    }

    fn as_slices(owned: &[Vec<u8>]) -> Vec<&[u8]> {
        owned.iter().map(Vec::as_slice).collect()
    }

    /// Builds over `owned` with shared params, so every filter here combines.
    fn build(owned: &[Vec<u8>]) -> Bloom001 {
        Bloom001::build(&as_slices(owned), &Params::new(10_000, 0.01)).unwrap()
    }

    #[test]
    fn union_holds_every_member_of_both_sides() {
        let left = keys("left", 500);
        let right = keys("right", 500);

        let merged = build(&left).union(&build(&right)).unwrap();

        for key in left.iter().chain(right.iter()) {
            assert!(merged.contains(key), "union lost {key:?}");
        }
    }

    #[test]
    fn union_is_commutative() {
        let a = build(&keys("a", 100));
        let b = build(&keys("b", 100));

        // Bitwise OR is commutative, so the bit arrays must match exactly.
        assert_eq!(a.union(&b).unwrap(), b.union(&a).unwrap());
    }

    #[test]
    fn union_with_self_is_unchanged() {
        let filter = build(&keys("x", 100));
        let doubled = filter.union(&filter).unwrap();

        assert_eq!(filter.bit_count(), doubled.bit_count());
        // OR against itself sets no new bit, so the estimate must not move.
        assert_eq!(filter.estimated_len(), doubled.estimated_len());
    }

    #[test]
    fn union_with_an_empty_filter_preserves_the_other_side() {
        let owned = keys("x", 100);
        let filter = build(&owned);
        let empty = build(&[]);

        let merged = filter.union(&empty).unwrap();

        for key in &owned {
            assert!(merged.contains(key));
        }
    }

    #[test]
    fn intersection_keeps_shared_keys() {
        let mut shared = keys("shared", 100);
        let mut only_a = keys("a-only", 100);
        let mut only_b = keys("b-only", 100);

        let mut set_a = shared.clone();
        set_a.append(&mut only_a);
        let mut set_b = shared.clone();
        set_b.append(&mut only_b);

        let common = build(&set_a).intersect(&build(&set_b)).unwrap();

        // No false negatives: every key in both sets survives the AND.
        for key in &mut shared {
            assert!(common.contains(key), "intersection lost shared {key:?}");
        }
    }

    #[test]
    fn intersection_of_disjoint_sets_is_nearly_empty() {
        let a = build(&keys("a", 200));
        let b = build(&keys("b", 200));

        let common = a.intersect(&b).unwrap();

        // Not asserted to be exactly zero: an unlucky overlap can leave a bit
        // standing. The point is that it collapses, not that it vanishes.
        assert!(
            common.estimated_len() < 20,
            "disjoint sets intersected to {} keys",
            common.estimated_len()
        );
    }

    #[test]
    fn intersection_is_commutative() {
        let a = build(&keys("a", 100));
        let b = build(&keys("b", 100));

        assert_eq!(a.intersect(&b).unwrap(), b.intersect(&a).unwrap());
    }

    #[test]
    fn set_ops_reject_a_different_bit_count() {
        let small = Bloom001::build(&[b"a"], &Params::new(10, 0.01)).unwrap();
        let large = Bloom001::build(&[b"b"], &Params::new(100_000, 0.01)).unwrap();

        assert!(matches!(
            small.union(&large),
            Err(Error::Incompatible {
                aspect: "bit_count",
                ..
            })
        ));
        assert!(small.intersect(&large).is_err());
        assert!(!small.is_compatible_with(&large));
    }

    #[test]
    fn set_ops_reject_a_different_seed() {
        // Same size, so only the seed differs: the bit arrays are the same
        // shape but mean different things, which is the subtler failure.
        let params = Params::new(1_000, 0.01);
        let a = Bloom001::build(&[b"a"], &params).unwrap();
        let b = Bloom001::build(&[b"b"], &params.with_seed(42)).unwrap();

        assert!(matches!(
            a.union(&b),
            Err(Error::Incompatible { aspect: "seed", .. })
        ));
    }

    #[test]
    fn compatible_filters_share_params() {
        let params = Params::new(1_000, 0.01);
        let a = Bloom001::build(&[b"a"], &params).unwrap();
        let b = Bloom001::build(&[b"b"], &params).unwrap();

        assert!(a.is_compatible_with(&b));
        assert!(a.union(&b).is_ok());
    }

    #[test]
    fn estimated_len_tracks_the_true_distinct_count() {
        for n in [10_usize, 100, 1_000, 5_000] {
            let owned = keys("k", n);
            let filter = Bloom001::build(&as_slices(&owned), &Params::new(n.max(1), 0.01)).unwrap();

            let estimate = filter.estimated_len() as f64;
            let error = (estimate - n as f64).abs() / n as f64;

            assert!(
                error < 0.10,
                "estimated {estimate} for {n} keys, off by {:.1}%",
                error * 100.0
            );
        }
    }

    #[test]
    fn estimated_len_counts_distinct_keys_not_insertions() {
        let owned = vec![b"same".to_vec(); 50];
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(1_000, 0.01)).unwrap();

        assert_eq!(filter.len(), 50, "len counts what was supplied");
        assert_eq!(filter.estimated_len(), 1, "one distinct key");
    }

    #[test]
    fn an_empty_filter_estimates_zero() {
        let empty = build(&[]);

        assert_eq!(empty.estimated_len(), 0);
        assert_eq!(empty.fill_ratio(), 0.0);
    }

    #[test]
    fn union_estimates_the_distinct_count_not_the_sum() {
        // Halves overlap completely, so the union holds 200 keys, not 400.
        let owned = keys("k", 200);
        let first = Bloom001::build(&as_slices(&owned[..150]), &Params::new(1_000, 0.01)).unwrap();
        let second = Bloom001::build(&as_slices(&owned[50..]), &Params::new(1_000, 0.01)).unwrap();

        let merged = first.union(&second).unwrap();

        assert_eq!(first.len() + second.len(), 300, "naive sum double-counts");
        let estimate = merged.len();
        assert!(
            (180..=220).contains(&estimate),
            "union reported {estimate} keys, expected about 200"
        );
    }

    #[test]
    fn union_reports_a_worse_rate_than_its_inputs() {
        let a = build(&keys("a", 2_000));
        let b = build(&keys("b", 2_000));

        let merged = a.union(&b).unwrap();

        // More keys in the same bits means a worse rate, and the filter has to
        // say so rather than repeating the rate it was built for.
        assert!(
            merged.false_positive_rate() > a.false_positive_rate(),
            "union rate {} did not exceed the input rate {}",
            merged.false_positive_rate(),
            a.false_positive_rate()
        );
    }

    #[test]
    fn jaccard_is_one_for_identical_key_sets() {
        let owned = keys("k", 500);
        let a = build(&owned);
        let b = build(&owned);

        assert_eq!(a.jaccard_similarity(&b).unwrap(), 1.0);
    }

    #[test]
    fn jaccard_is_near_zero_for_disjoint_key_sets() {
        let a = build(&keys("a", 500));
        let b = build(&keys("b", 500));

        let similarity = a.jaccard_similarity(&b).unwrap();
        assert!(similarity < 0.05, "disjoint sets scored {similarity}");
    }

    #[test]
    fn jaccard_tracks_a_known_half_overlap() {
        // 500 keys each, 250 shared: true Jaccard is 250/750 ≈ 0.333.
        let owned = keys("k", 750);
        let a = Bloom001::build(&as_slices(&owned[..500]), &Params::new(10_000, 0.001)).unwrap();
        let b = Bloom001::build(&as_slices(&owned[250..]), &Params::new(10_000, 0.001)).unwrap();

        let similarity = a.jaccard_similarity(&b).unwrap();

        assert!(
            (0.25..=0.45).contains(&similarity),
            "expected about 0.33, got {similarity}"
        );
    }

    #[test]
    fn jaccard_of_two_empty_filters_is_one() {
        let a = build(&[]);
        let b = build(&[]);

        // They agree completely: both hold nothing.
        assert_eq!(a.jaccard_similarity(&b).unwrap(), 1.0);
    }

    #[test]
    fn jaccard_is_symmetric() {
        let a = build(&keys("a", 300));
        let b = build(&keys("b", 300));

        assert_eq!(
            a.jaccard_similarity(&b).unwrap(),
            b.jaccard_similarity(&a).unwrap()
        );
    }

    #[test]
    fn containment_is_one_for_a_subset() {
        let owned = keys("k", 1_000);
        let subset =
            Bloom001::build(&as_slices(&owned[..100]), &Params::new(10_000, 0.001)).unwrap();
        let superset = Bloom001::build(&as_slices(&owned), &Params::new(10_000, 0.001)).unwrap();

        assert_eq!(subset.containment_in(&superset).unwrap(), 1.0);
    }

    #[test]
    fn containment_is_asymmetric() {
        let owned = keys("k", 1_000);
        let subset =
            Bloom001::build(&as_slices(&owned[..100]), &Params::new(10_000, 0.001)).unwrap();
        let superset = Bloom001::build(&as_slices(&owned), &Params::new(10_000, 0.001)).unwrap();

        // The large set is not contained in the small one, which is the whole
        // reason this exists alongside Jaccard.
        let backwards = superset.containment_in(&subset).unwrap();
        assert!(
            backwards < 0.25,
            "superset scored {backwards} inside subset"
        );
    }

    #[test]
    fn an_empty_filter_is_contained_in_anything() {
        let empty = build(&[]);
        let full = build(&keys("k", 100));

        assert_eq!(empty.containment_in(&full).unwrap(), 1.0);
    }

    #[test]
    fn similarity_measures_reject_incompatible_filters() {
        let small = Bloom001::build(&[b"a"], &Params::new(10, 0.01)).unwrap();
        let large = Bloom001::build(&[b"b"], &Params::new(100_000, 0.01)).unwrap();

        assert!(small.jaccard_similarity(&large).is_err());
        assert!(small.containment_in(&large).is_err());
    }

    #[test]
    fn fill_ratio_grows_with_the_key_count() {
        let sparse = build(&keys("k", 10));
        let dense = build(&keys("k", 5_000));

        assert!(sparse.fill_ratio() < dense.fill_ratio());
        assert!((0.0..=1.0).contains(&dense.fill_ratio()));
    }

    #[test]
    fn a_saturated_filter_estimates_a_bounded_count() {
        // Deliberately overloaded: far more keys than the sizing allows, so
        // nearly every bit is set. The estimator must not return an infinity
        // or panic on the cast.
        let owned = keys("k", 20_000);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(10, 0.5)).unwrap();

        let estimate = filter.estimated_len();
        assert!(estimate > 0, "a full filter cannot hold nothing");
    }

    #[test]
    fn a_union_round_trips_through_encoding() {
        let merged = build(&keys("a", 100))
            .union(&build(&keys("b", 100)))
            .unwrap();

        let mut bytes = Vec::new();
        merged.encode(&mut bytes).unwrap();

        // The corrected `len` has to survive the trip, since the decoder bounds
        // it against the bit count.
        assert_eq!(Bloom001::decode(&bytes).unwrap(), merged);
    }
}
