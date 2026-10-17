// This file must FAIL to compile.
//
// Kappa does not implement From<&str> or From<String>.
// The inner String field is private. Construction goes through
// parse() (validates format) or compute() (hashes bytes).
//
// If this file compiles, any code can fabricate content addresses
// that do not correspond to any stored content.

fn main() {
    // Attempt From<String> conversion. Must fail because the impl does not exist.
    let _k: kappa_store::kappa::Kappa = "sha256:not_validated".to_string().into();
}
