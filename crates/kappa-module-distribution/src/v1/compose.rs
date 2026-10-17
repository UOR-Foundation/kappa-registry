use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, binary_response, blocking, execute, json_response, path_param,
    principal, read_json_with_bytes, resolve_ns_read, store, write_target,
};
use kappa_store::edge::{BuiltinRelation, EdgeInput, EdgeRelation, SemanticRelation, semantic};
use kappa_store::kappa::Kappa;
use kappa_store::{Execution, StoreError, VerifiedContent};

/// Bound on a composition request document.
const MAX_COMPOSE_BODY: usize = 1024 * 1024;

/// Witness header: width in bytes of the label field.
const WITNESS_LABEL_WIDTH: u16 = 71;
/// Witness header: width in bytes of the fingerprint field.
const WITNESS_FINGERPRINT_WIDTH: u16 = 32;
/// Witness header: format version.
const WITNESS_VERSION: u16 = 1;

/// E6 class tags: first digest byte mod 9 at most 7, otherwise the second.
const E6_LOW_CLASS_TAG: u8 = 0x05;
const E6_HIGH_CLASS_TAG: u8 = 0x06;
const E6_CLASS_MODULUS: u8 = 9;
const E6_LOW_CLASS_MAX: u8 = 7;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(Method::POST, "/v2/{*ns}/compose/{op}", compose))
        .route(dist_route!(
            Method::GET,
            "/v2/{*ns}/witnesses/{kappa}",
            witness
        ))
}

#[derive(serde::Deserialize)]
struct ComposeRequest {
    operands: Vec<String>,
}

/// A composition operation and its canonical form.
#[derive(Clone, Copy)]
enum Operation {
    G2,
    F4,
    E6,
    E7,
    E8,
}

impl Operation {
    fn parse(token: &str) -> Result<Self, HandlerError> {
        match token {
            "g2" => Ok(Self::G2),
            "f4" => Ok(Self::F4),
            "e6" => Ok(Self::E6),
            "e7" => Ok(Self::E7),
            "e8" => Ok(Self::E8),
            other => Err(HandlerError::bad_request(format!(
                "unknown operation {other}; expected g2, f4, e6, e7, or e8"
            ))),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::G2 => "g2",
            Self::F4 => "f4",
            Self::E6 => "e6",
            Self::E7 => "e7",
            Self::E8 => "e8",
        }
    }

    const fn arity(self) -> usize {
        match self {
            Self::G2 => 2,
            Self::F4 | Self::E6 | Self::E7 | Self::E8 => 1,
        }
    }

    /// Canonical bytes of the composition. `operands` has this operation's
    /// arity and a single σ-axis.
    fn canonical(self, operands: &[Kappa]) -> Result<Vec<u8>, HandlerError> {
        match (self, operands) {
            (Self::G2, [a, b]) => Ok(canonical_g2(a, b)),
            (Self::F4, [a]) => Ok(canonical_f4(a)),
            (Self::E6, [a]) => Ok(canonical_e6(a)),
            (Self::E7, [a]) => canonical_e7(a),
            (Self::E8, [a]) => Ok(a.to_string().into_bytes()),
            _ => Err(HandlerError::internal(format!(
                "{} canonicalized with {} operands",
                self.name(),
                operands.len()
            ))),
        }
    }
}

async fn compose(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (ComposeRequest, _) = read_json_with_bytes(body, MAX_COMPOSE_BODY).await?;
    let target = write_target(cx)?;
    let operation = Operation::parse(&path_param(cx, "op")?)?;

    if req.operands.len() != operation.arity() {
        return Err(HandlerError::bad_request(format!(
            "{} requires {} operand(s), got {}",
            operation.name(),
            operation.arity(),
            req.operands.len()
        )));
    }
    let operands = req
        .operands
        .iter()
        .map(|operand| Kappa::parse(operand))
        .collect::<Result<Vec<_>, _>>()?;
    let axis = operands[0].axis();
    if operands.iter().any(|operand| operand.axis() != axis) {
        return Err(HandlerError::protocol(
            StatusCode::UNPROCESSABLE_ENTITY,
            "AXIS_MISMATCH",
            "composition operands differ in sigma-axis",
        ));
    }

    let canonical = operation.canonical(&operands)?;
    let composed = Kappa::compute(axis, &canonical)?;
    let witness_data = witness_blob(&canonical);
    let witness = Kappa::compute(axis, &witness_data)?;

    let composition = Composition {
        composed: composed.clone(),
        canonical,
        witness: witness.clone(),
        witness_data,
        operands,
        operation,
        asserter: principal(cx),
    };
    // The composed object, its witness, their metadata, and every edge
    // publish in one epoch.
    let committed = execute(cx, target, &raw, move |execution| {
        composition.write(execution)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let resp = serde_json::json!({
        "composed": composed.to_string(),
        "witness": witness.to_string(),
        "operands": req.operands,
        "operation": operation.name(),
    });
    let mut response = json_response(StatusCode::OK, &resp)?;
    committed.annotate(&mut response);
    Ok(response)
}

/// Everything one composition writes.
struct Composition {
    composed: Kappa,
    canonical: Vec<u8>,
    witness: Kappa,
    witness_data: Vec<u8>,
    operands: Vec<Kappa>,
    operation: Operation,
    asserter: Kappa,
}

impl Composition {
    /// The composed object and its witness are records this handler
    /// computed; they are installed as verified content the execution holds.
    fn write(&self, execution: &mut dyn Execution) -> Result<(), StoreError> {
        let now_ms = execution.now().as_i64();
        execution.blob_put(&VerifiedContent::verify(&self.composed, &self.canonical)?)?;
        kappa_store::blob_meta_put_indexed(
            execution,
            &self.composed,
            "object-type",
            "composition",
        )?;
        execution.blob_put(&VerifiedContent::verify(&self.witness, &self.witness_data)?)?;
        kappa_store::blob_meta_put_indexed(execution, &self.witness, "object-type", "witness")?;
        let operation_meta =
            serde_json::to_vec(&serde_json::json!({ "operation": self.operation.name() }))
                .map_err(|error| StoreError::Internal(format!("edge metadata: {error}")))?;
        let mut edges: Vec<EdgeInput> = self
            .operands
            .iter()
            .map(|operand| EdgeInput {
                source: self.composed.clone(),
                target: operand.clone(),
                relation: EdgeRelation::Semantic(SemanticRelation(semantic::COMPOSED_OF.into())),
                created_at_ms: now_ms,
                asserter: self.asserter.clone(),
                metadata: Some(operation_meta.clone()),
            })
            .collect();
        edges.push(EdgeInput {
            source: self.composed.clone(),
            target: self.witness.clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::WitnessReceipt),
            created_at_ms: now_ms,
            asserter: self.asserter.clone(),
            metadata: None,
        });
        execution.edge_put_batch(&edges)?;
        Ok(())
    }
}

async fn witness(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let kappa = Kappa::parse(&path_param(cx, "kappa")?)?;

    let s = store(cx);
    let query = kappa_store::edge::EdgeQuery {
        anchor: kappa,
        direction: kappa_store::edge::Direction::Outbound,
        relation: Some(EdgeRelation::Builtin(BuiltinRelation::WitnessReceipt)),
        asserter: None,
    };
    let edges = blocking({
        let s = s.clone();
        let n = ns.clone();
        move || s.edge_query(&n, &query, &kappa_store::PageRequest::first(1))
    })
    .await?;

    let witness_kappa = edges
        .items
        .first()
        .map(|e| e.target().clone())
        .ok_or_else(|| HandlerError::not_found("witness not found"))?;

    let content = blocking({
        let s = s.clone();
        let wk = witness_kappa.clone();
        move || s.blob_get_in(&ns, &wk)
    })
    .await?;

    let mut resp = binary_response(StatusCode::OK, "application/octet-stream", content)?;
    resp.headers_mut().insert(
        "x-kappa-label",
        witness_kappa.to_string().parse().map_err(|error| {
            HandlerError::internal(format!("invalid witness response header: {error}"))
        })?,
    );
    Ok(resp)
}

/// The lexicographically smaller concatenation, so g2 commutes.
fn canonical_g2(a: &Kappa, b: &Kappa) -> Vec<u8> {
    let (a, b) = (a.to_string(), b.to_string());
    let ab = [a.as_bytes(), b.as_bytes()].concat();
    let ba = [b.as_bytes(), a.as_bytes()].concat();
    ab.min(ba)
}

/// The smaller of a label and its complement, so f4 is mirror-invariant.
fn canonical_f4(a: &Kappa) -> Vec<u8> {
    let (label, complement) = (a.to_string(), a.complement().to_string());
    label.min(complement).into_bytes()
}

/// The label prefixed by the class tag of its first digest byte.
fn canonical_e6(a: &Kappa) -> Vec<u8> {
    let first = a.digest_bytes()[0];
    let tag = if first % E6_CLASS_MODULUS <= E6_LOW_CLASS_MAX {
        E6_LOW_CLASS_TAG
    } else {
        E6_HIGH_CLASS_TAG
    };
    let label = a.to_string();
    let mut out = Vec::with_capacity(1 + label.len());
    out.push(tag);
    out.extend_from_slice(label.as_bytes());
    out
}

/// The label whose digest is the least ordering of the digest's quarters.
fn canonical_e7(a: &Kappa) -> Result<Vec<u8>, HandlerError> {
    let digest = a.digest_bytes();
    if !digest.len().is_multiple_of(4) {
        return Err(HandlerError::bad_request(format!(
            "e7 needs a digest divisible into quarters; {} has {} bytes",
            a.axis().as_str(),
            digest.len()
        )));
    }
    let quarter = digest.len() / 4;
    let quarters: Vec<&[u8]> = digest.chunks(quarter).collect();
    let mut best: Option<Vec<u8>> = None;
    for order in permutations_of_four() {
        let candidate: Vec<u8> = order.iter().flat_map(|&i| quarters[i]).copied().collect();
        if best.as_ref().is_none_or(|current| candidate < *current) {
            best = Some(candidate);
        }
    }
    let best = best.ok_or_else(|| HandlerError::internal("no quarter ordering"))?;
    Ok(format!("{}:{}", a.axis().as_str(), hex::encode(best)).into_bytes())
}

/// Every ordering of the indices 0 through 3.
fn permutations_of_four() -> Vec<[usize; 4]> {
    let mut orders = Vec::with_capacity(24);
    for a in 0..4 {
        for b in (0..4).filter(|&b| b != a) {
            for c in (0..4).filter(|&c| c != a && c != b) {
                let d = 6 - a - b - c;
                orders.push([a, b, c, d]);
            }
        }
    }
    orders
}

fn witness_blob(trace: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(6 + trace.len());
    w.extend_from_slice(&WITNESS_LABEL_WIDTH.to_le_bytes());
    w.extend_from_slice(&WITNESS_FINGERPRINT_WIDTH.to_le_bytes());
    w.extend_from_slice(&WITNESS_VERSION.to_le_bytes());
    w.extend_from_slice(trace);
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_orderings_are_the_24_distinct_permutations() {
        let orders = permutations_of_four();
        assert_eq!(orders.len(), 24);
        let unique: std::collections::BTreeSet<_> = orders.iter().collect();
        assert_eq!(unique.len(), 24);
        for order in &orders {
            let mut sorted = *order;
            sorted.sort_unstable();
            assert_eq!(sorted, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn arity_is_checked_before_canonicalization() -> Result<(), HandlerError> {
        let label = Kappa::sha256(b"operand");
        assert!(
            Operation::G2
                .canonical(std::slice::from_ref(&label))
                .is_err()
        );
        let g2 = Operation::G2.canonical(&[label.clone(), Kappa::sha256(b"other")])?;
        let swapped = Operation::G2.canonical(&[Kappa::sha256(b"other"), label])?;
        assert_eq!(g2, swapped);
        Ok(())
    }
}
