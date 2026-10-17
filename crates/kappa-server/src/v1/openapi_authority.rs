//! OpenAPI documentation of the node authority operations: rotation and
//! status. Written for administrators and automation: what each outcome
//! means for which authority signs and what it is authorized for, and
//! what to do next.

use serde_json::{Value, json};

fn error() -> Value {
    json!({"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}})
}

/// The four follow-up guarantees, as reported by rotation and status.
fn completion() -> Value {
    json!({
        "type": "object",
        "description": "Whether each guarantee that completes the node's authority holds. Readiness (/v2/_health/ready) reports ready only when all four hold and the node signs with the committed authority, and each readiness probe retries the incomplete ones.",
        "properties": {
            "custody": {"type": "boolean", "description": "The node's key store durably selects the current authority's key, so a restart signs with it."},
            "key_removal": {"type": "boolean", "description": "No retired or abandoned node private key remains in the key store."},
            "authorization": {"type": "boolean", "description": "The current authority's identity, _root administrator capability and root-token delegation are published."},
            "revocation": {"type": "boolean", "description": "No _root capability or delegation issued by a retired authority remains published, so nothing a retired key granted still authorizes."}
        },
        "required": ["custody", "key_removal", "authorization", "revocation"]
    })
}

pub fn node_rotation(op: &mut Value) {
    op["description"] = json!(
        "Requires _root administrator authority. Generates a new node signing key and commits an authenticated succession, signed by both the current and the new key, in the store's authority history. Once committed, every epoch the node signs uses the new authority; epochs signed before remain verifiable under the authority that signed them. The retired authority loses its _root capability and every delegation it issued; the configured root-token delegate is delegated again by the new authority, so the root token keeps its authorization.\n\nNot idempotent: every accepted request performs a new rotation. If a response is lost, read GET /_node/authority to learn the current authority before submitting another request.\n\nA 200 means the rotation committed. Its completion object reports which follow-up guarantees already hold; any that do not are retried by readiness probes and on restart, and GET /_node/authority reports their progress."
    );
    op["requestBody"] = json!({
        "required": false,
        "content": {"application/json": {"schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"algorithm": {"type": "string", "enum": crate::authority_routes::ALGORITHMS, "description": "Algorithm of the new key; absent, the configured one."}}
        }}}
    });
    op["responses"]["200"]["description"] =
        json!("Committed. The node signs with the current authority.");
    op["responses"]["200"]["content"]["application/json"]["schema"] = json!({
        "type": "object",
        "properties": {
            "retired": {"type": "string", "description": "Anchor of the authority this rotation retired."},
            "current": {"type": "string", "description": "Anchor of the authority the node now signs with."},
            "completion": completion()
        },
        "required": ["retired", "current", "completion"]
    });
    op["responses"]["400"] = json!({"description": "The body is not a JSON object whose only member is a supported algorithm string; nothing was attempted. UNSUPPORTED_ALGORITHM: the key store does not support the algorithm; no rotation committed and the message states whether a generated key remains.", "content": error()});
    op["responses"]["403"] = json!({"description": "The caller lacks _root administrator authority. Nothing was attempted.", "content": error()});
    op["responses"]["409"] = json!({"description": "ROTATION_REJECTED: the store refused the rotation, for the reason the message states. No rotation committed and the current authority remains active. The message states whether the generated key was removed; if not, reconciliation removes it and status reports key_removal false until then.", "content": error()});
    op["responses"]["500"] = json!({"description": "ROTATION_FAILED: the rotation failed before it could commit. No rotation committed and the current authority remains active. The message states whether a generated key remains or the key store could not be brought into agreement with the current authority; status reports key_removal or custody false until reconciliation completes them, and readiness reports not ready meanwhile.", "content": error()});
    op["responses"]["503"] = json!({"description": "The node signs nothing until it restarts; on restart it selects the authority the store committed. Read GET /_node/authority after restarting before any further rotation. ROTATION_UNRESOLVED: whether this rotation committed is unknown; both keys are kept until the restart decides. AUTHORITY_UNRESOLVED or AUTHORITY_INTERRUPTED: an earlier authority change left the authority unknown; nothing was attempted. AUTHORITY_DIVERGED: the node's live authority differs from the committed one; nothing was attempted, and every signing operation is refused until the restart.", "content": error()});
}

pub fn node_authority_status(op: &mut Value) {
    op["description"] = json!(
        "Requires _root read authority. The authority the store established and whether its commitment is known, whether the node signs with it, every retired authority, and which follow-up guarantees hold for it, all observed at one instant: a rotation in progress completes before status is read. After an unresolved rotation and a restart, this is how an operator learns which authority the store committed."
    );
    op["responses"]["200"]["description"] = json!("The node's authority.");
    op["responses"]["200"]["content"]["application/json"]["schema"] = json!({
        "type": "object",
        "properties": {
            "current": {"type": "string", "description": "Anchor of the authority the store last established. When commit is known, this is the committed authority. When commit is unknown, a rotation from it may or may not have committed; a restart selects whichever the store's history holds."},
            "commit": {"type": "string", "enum": ["known", "unknown"], "description": "known: current is the store's committed authority. unknown: a rotation from current has an unknown outcome on this process; restart the node."},
            "availability": {
                "type": "string",
                "enum": ["active", "unresolved", "interrupted", "diverged"],
                "description": "active: the node signs with the committed authority. unresolved: a rotation's outcome is unknown and the node signs nothing until it restarts. interrupted: an authority change was interrupted and the node signs nothing until it restarts. diverged: the node's live authority differs from the committed one and the node signs nothing until it restarts."
            },
            "live": {"type": ["string", "null"], "description": "For unresolved, the authority the node signed with before the unknown rotation; for diverged, the live authority; otherwise null."},
            "retired": {"type": "array", "items": {"type": "string"}, "description": "Every authority the established history retired, oldest first."},
            "completion": completion()
        },
        "required": ["current", "commit", "availability", "live", "retired", "completion"]
    });
    op["responses"]["403"] =
        json!({"description": "The caller lacks _root read authority.", "content": error()});
    op["responses"]["503"] = json!({"description": "AUTHORITY_INTERRUPTED: an authority change was interrupted, so the node's authority cannot be observed; restart the node.", "content": error()});
}
