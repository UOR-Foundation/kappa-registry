use super::*;
use kappa_types::edge::{BuiltinRelation, EdgeRelation, SemanticRelation};

fn edge(seed: u8, relation: EdgeRelation, asserter: Kappa) -> Edge {
    let input = EdgeInput {
        source: Kappa::sha256(b"source"),
        target: Kappa::sha256(&[seed]),
        relation,
        asserter,
        created_at_ms: 7,
        metadata: None,
    };
    Edge {
        kappa: Kappa::sha256(&canonical_bytes(&input)),
        input,
    }
}

#[test]
fn selective_indexes_filter_before_record_dereference() -> Result<(), StoreError> {
    let owner = Kappa::sha256(b"owner");
    let other = Kappa::sha256(b"other");
    let relation = EdgeRelation::Semantic(SemanticRelation("https://example.org/owns".into()));
    let selected = edge(0, relation.clone(), owner.clone());
    let mut state = EdgeState::default();
    state.insert(selected.clone());
    for seed in 1..64 {
        let unwanted = edge(
            seed,
            EdgeRelation::Builtin(BuiltinRelation::Owns),
            other.clone(),
        );
        state.insert(unwanted.clone());
        // Missing unselected records force index selection before dereference.
        state.records.remove(&unwanted.kappa);
    }
    for (relation_filter, asserter_filter) in [
        (Some(relation.clone()), None),
        (None, Some(owner.clone())),
        (Some(relation), Some(owner)),
    ] {
        let query = EdgeQuery {
            anchor: selected.source().clone(),
            direction: Direction::Both,
            relation: relation_filter,
            asserter: asserter_filter,
        };
        let mut found = Vec::new();
        state.visit(&query, None, |record| {
            found.push(record.kappa.clone());
            true
        })?;
        assert_eq!(found.as_slice(), std::slice::from_ref(&selected.kappa));
        assert!(state.remove(&selected.kappa).is_some());
        state.visit(&query, None, |_| panic!("deleted index entry"))?;
        state.insert(selected.clone());
    }
    Ok(())
}
