mod blob;
mod canonical;
mod edge;
mod epoch;
mod identity;
mod identity_substrate;
mod identity_tier2;
mod kappa_label;
mod merkle;
mod namespace;
mod replay;
mod sequence;
mod support;
mod tag;
mod verified;

#[test]
fn compile_fail_sealed_constructors() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/v1/compile_fail/*.rs");
}
