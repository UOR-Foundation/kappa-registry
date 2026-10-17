// C-7: Hint cannot answer absence (compile-fail).
//
// FF-8: An absence proof derived from unverified bytes would
// silently degrade the audit claim. Hint exposes seek and
// nothing else. contains, len, and KappaCursor are absent
// by construction.

fn main() {
    let h = kappa_succinct::Hint::from_unverified_bytes(&[]).unwrap();

    // These MUST NOT compile:
    let _ = h.contains(&[0u8]);  //~ ERROR
    let _ = h.len();             //~ ERROR
}
