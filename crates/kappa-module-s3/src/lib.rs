#![forbid(unsafe_code)]
//! S3-compatible protocol module for kappa-registry.
//!
//! Pure functions producing XML byte strings from store query results.
//! No HTTP types. No async. WASM-portable.

pub mod xml;
pub mod list;

pub use list::{list_objects_v2, ListObjectsV2Request, ListObjectsV2Response, ObjectEntry};
pub use xml::{
    encode_complete_multipart_xml, encode_copy_result_xml, encode_delete_result_xml,
    encode_initiate_multipart_xml, encode_list_objects_v2_xml, encode_list_parts_xml,
    encode_s3_error_xml,
};
