// This file must FAIL to compile.
//
// NamespaceRef does not implement From<&str> or From<String>.
// All fields are private. Construction goes through deterministic(),
// generate(), or resolved() -- never from an arbitrary string.
//
// If this file compiles, namespace path traversal attacks are
// structurally possible (e.g., "../../etc/passwd" as a namespace).

fn main() {
    // Attempt From<&str> conversion. Must fail because the impl does not exist.
    let _ns: kappa_store::namespace::NamespaceRef = "arbitrary-string".into();
}
