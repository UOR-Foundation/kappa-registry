// This file must FAIL to compile.
// VerifiedContent has a private _seal field -- external crates
// cannot construct it via struct literal syntax. The only way
// to obtain a VerifiedContent is through compute() or verify().

fn main() {
    let _v = kappa_core::verified::VerifiedContent {
        label: todo!(),
        content: vec![],
        _seal: todo!(),
    };
}
