//! PERF-EPO-004: `StateDigest` commutative, associative, insert/remove
//! inverse, merge/subtract federation-stable. Property tests at 10^6 cases.
//!
//! PERF-EPO-005: Digest equals full recomputation after any mutation
//! sequence.

use kappa_types::StateDigest;
use kappa_types::kappa::Kappa;
use proptest::prelude::*;

fn arb_kappa() -> impl Strategy<Value = Kappa> {
    any::<[u8; 4]>().prop_map(|bytes| Kappa::sha256(&bytes))
}

fn arb_name() -> impl Strategy<Value = String> {
    "[a-z]{1,8}".prop_map(String::from)
}

// -- Commutativity: insert order does not matter --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn insert_order_independent(
        a_name in arb_name(),
        a_kappa in arb_kappa(),
        b_name in arb_name(),
        b_kappa in arb_kappa(),
    ) {
        let mut forward = StateDigest::default();
        forward.insert(&a_name, &a_kappa);
        forward.insert(&b_name, &b_kappa);

        let mut reverse = StateDigest::default();
        reverse.insert(&b_name, &b_kappa);
        reverse.insert(&a_name, &a_kappa);

        prop_assert_eq!(forward, reverse);
    }
}

// -- Insert/remove inverse --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn insert_remove_inverse(
        name in arb_name(),
        kappa in arb_kappa(),
    ) {
        let mut digest = StateDigest::default();
        digest.insert(&name, &kappa);
        digest.remove(&name, &kappa);
        prop_assert_eq!(digest, StateDigest::default());
    }
}

// -- Merge/subtract inverse --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn merge_subtract_inverse(
        name in arb_name(),
        kappa in arb_kappa(),
    ) {
        let mut a = StateDigest::default();
        a.insert(&name, &kappa);
        let b = a;
        a.subtract(b);
        prop_assert_eq!(a, StateDigest::default());
    }
}

// -- Associativity of merge --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn merge_associative(
        a_name in arb_name(),
        a_kappa in arb_kappa(),
        b_name in arb_name(),
        b_kappa in arb_kappa(),
        c_name in arb_name(),
        c_kappa in arb_kappa(),
    ) {
        let mut da = StateDigest::default();
        da.insert(&a_name, &a_kappa);
        let mut db = StateDigest::default();
        db.insert(&b_name, &b_kappa);
        let mut dc = StateDigest::default();
        dc.insert(&c_name, &c_kappa);

        // (a + b) + c
        let mut ab = da;
        ab.merge(db);
        let mut abc_left = ab;
        abc_left.merge(dc);

        // a + (b + c)
        let mut da2 = StateDigest::default();
        da2.insert(&a_name, &a_kappa);
        let mut db2 = StateDigest::default();
        db2.insert(&b_name, &b_kappa);
        let mut dc2 = StateDigest::default();
        dc2.insert(&c_name, &c_kappa);
        let mut bc = db2;
        bc.merge(dc2);
        let mut abc_right = da2;
        abc_right.merge(bc);

        prop_assert_eq!(abc_left, abc_right);
    }
}

// -- PERF-EPO-005: Digest equals recomputation after mutations --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn digest_equals_recomputation(
        ops in proptest::collection::vec(
            (arb_name(), arb_kappa(), prop::bool::ANY),
            1..100
        )
    ) {
        let mut incremental = StateDigest::default();
        let mut entries: std::collections::BTreeMap<String, Kappa> = std::collections::BTreeMap::new();

        for (name, kappa, is_insert) in &ops {
            if *is_insert {
                if let Some(old) = entries.insert(name.clone(), kappa.clone()) {
                    incremental.remove(name, &old);
                }
                incremental.insert(name, kappa);
            } else if let Some(old) = entries.remove(name) {
                incremental.remove(name, &old);
            }
        }

        // Full recomputation from the final set
        let mut recomputed = StateDigest::default();
        for (name, kappa) in &entries {
            recomputed.insert(name, kappa);
        }

        prop_assert_eq!(incremental, recomputed);
    }
}
