use kappa_types::ProtocolId;
use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("s3").expect("valid protocol id"));

/// S3-compatible API protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &PROTOCOL_ID
}

pub mod detect;
pub mod handlers;
pub mod list;
pub mod xml;

pub use handlers::register;
pub use xml::{
    PartInfo, encode_complete_multipart_xml, encode_copy_result_xml, encode_delete_result_xml,
    encode_initiate_multipart_xml, encode_list_objects_v2_xml, encode_list_parts_xml,
    encode_s3_error_xml,
};
