// This file must FAIL to compile.
//
// NamespaceRef fields (id, display_name, protocol) are all private.
// External crates cannot construct a NamespaceRef via struct literal.
// Construction must go through deterministic(), generate(), or
// resolved() which enforce UUID format invariants.
//
// If this file compiles, arbitrary byte arrays can be used as
// namespace identifiers bypassing UUID version/variant validation.

fn main() {
    let _ns = kappa_store::namespace::NamespaceRef {
        id: [0u8; 16],
        display_name: "fabricated".to_string(),
        protocol: None,
    };
}
