//! Narinfo text codec: parsing, serialization, and fingerprinting.

use kappa_module_nix::narinfo::{NarInfo, NarInfoError};

type TestResult = Result<(), NarInfoError>;

const LIBIDN2_NARINFO: &str = "\
StorePath: /nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2\n\
URL: nar/010zh5j819qyz6zai6h2hn3d7i406g00m2g4g62bq7m8g91553yb.nar.xz\n\
Compression: xz\n\
FileHash: sha256:010zh5j819qyz6zai6h2hn3d7i406g00m2g4g62bq7m8g91553yb\n\
FileSize: 63248\n\
NarHash: sha256:1npw0jz1cw4k9x25f2vsdhsa5cf9568j46bpz2768a1izqj5n9lf\n\
NarSize: 260816\n\
References: 0z7sqj4pilbqyp45ix5b0mdgn9xlb024-libunistring-0.9.10 r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2\n\
Deriver: 0n91syjwrhmng41f8d23ad0sl4a6ic4g-libidn2-2.3.2.drv\n\
Sig: cache.nixos.org-1:G9PxMT0/nd9ELwL3BBeqWtb2ohMiqw4T4FUwFlAU9M0E45mKg77BzL9gJQ3wH4oYtsa61MV5uzNLPFvK8ZbyCA==\n";

#[test]
fn roundtrip_real_narinfo() -> TestResult {
    let parsed = NarInfo::parse(LIBIDN2_NARINFO)?;
    assert_eq!(parsed.store_path.name(), "libidn2-2.3.2");
    assert_eq!(parsed.compression, "xz");
    assert_eq!(parsed.references.len(), 2);
    assert_eq!(parsed.nar_size, 260_816);
    assert_eq!(
        parsed.deriver.as_deref(),
        Some("0n91syjwrhmng41f8d23ad0sl4a6ic4g-libidn2-2.3.2.drv")
    );
    assert_eq!(parsed.signatures.len(), 1);
    assert_eq!(parsed.to_narinfo_string(), LIBIDN2_NARINFO);
    Ok(())
}

#[test]
fn empty_references_roundtrips() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
    let parsed = NarInfo::parse(text)?;
    assert!(parsed.references.is_empty());
    assert_eq!(parsed.to_narinfo_string(), text);
    Ok(())
}

#[test]
fn rejects_missing_store_path() {
    let text = "\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::MissingField("StorePath"))
    ));
}

#[test]
fn rejects_missing_nar_hash() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarSize: 100\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::MissingField("NarHash"))
    ));
}

#[test]
fn rejects_missing_url() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::MissingField("URL"))
    ));
}

#[test]
fn rejects_zero_nar_size() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 0\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::MissingField("NarSize"))
    ));
}

#[test]
fn rejects_duplicate_references() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: foo-bar\n\
References: baz-qux\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::DuplicateField("References"))
    ));
}

#[test]
fn rejects_duplicate_ca() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
CA: fixed:r:sha256:0000000000000000000000000000000000000000000000000000\n\
CA: fixed:r:sha256:1111111111111111111111111111111111111111111111111111\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::DuplicateField("CA"))
    ));
}

#[test]
fn duplicate_store_path_last_wins() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first\n\
StorePath: /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
    assert_eq!(NarInfo::parse(text)?.store_path.name(), "second");
    Ok(())
}

#[test]
fn ignores_unknown_fields() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
System: x86_64-linux\n\
UnknownField: whatever\n";
    assert_eq!(NarInfo::parse(text)?.compression, "none");
    Ok(())
}

#[test]
fn unknown_deriver_becomes_none() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
Deriver: unknown-deriver\n";
    assert_eq!(NarInfo::parse(text)?.deriver, None);
    Ok(())
}

#[test]
fn missing_compression_defaults_bzip2() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
    assert_eq!(NarInfo::parse(text)?.compression, "bzip2");
    Ok(())
}

#[test]
fn fingerprint_format() -> TestResult {
    let parsed = NarInfo::parse(LIBIDN2_NARINFO)?;
    assert_eq!(
        parsed.fingerprint(),
        "1;/nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2;\
         sha256:1npw0jz1cw4k9x25f2vsdhsa5cf9568j46bpz2768a1izqj5n9lf;260816;\
         /nix/store/0z7sqj4pilbqyp45ix5b0mdgn9xlb024-libunistring-0.9.10,\
         /nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2"
    );
    Ok(())
}

#[test]
fn store_path_hash_is_32_chars() -> TestResult {
    let hash = NarInfo::parse(LIBIDN2_NARINFO)?.store_path_hash();
    assert_eq!(hash.len(), 32);
    assert_eq!(hash, "r5sjd57x0r07bwgipryaxqdkx1gglhiy");
    Ok(())
}

#[test]
fn multiple_signatures_preserved_in_order() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
Sig: key1:AAAA\n\
Sig: key2:BBBB\n";
    assert_eq!(
        NarInfo::parse(text)?.signatures,
        vec!["key1:AAAA".to_string(), "key2:BBBB".to_string()]
    );
    Ok(())
}

#[test]
fn ca_roundtrips() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
CA: fixed:r:sha256:0000000000000000000000000000000000000000000000000000\n";
    let parsed = NarInfo::parse(text)?;
    assert_eq!(
        parsed.ca.as_deref(),
        Some("fixed:r:sha256:0000000000000000000000000000000000000000000000000000")
    );
    assert_eq!(parsed.to_narinfo_string(), text);
    Ok(())
}

#[test]
fn rejects_line_without_colon() {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
this line has no colon\n\
URL: nar/test.nar\n";
    assert!(matches!(
        NarInfo::parse(text),
        Err(NarInfoError::MalformedLine(_))
    ));
}

#[test]
fn value_with_no_space_after_colon() -> TestResult {
    let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL:nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
    assert_eq!(NarInfo::parse(text)?.url, "nar/test.nar");
    Ok(())
}
