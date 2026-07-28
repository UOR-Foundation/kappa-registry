//! OpenAPI description and Scalar integration for the registry API.
//!
//! The dispatcher is centralized in `lib.rs`, so the public protocol is kept
//! in a compact route catalog here instead of annotating framework handlers.

use axum::{routing::get, Router};
use scalar_api_reference::axum::router as scalar_router;
use serde_json::{json, Map, Value};
use utoipa::openapi::OpenApi;

const BINARY: &str = "application/octet-stream";
const JSON: &str = "application/json";

pub async fn json() -> axum::Json<OpenApi> {
    axum::Json(document())
}

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let configuration = json!({
        "url": "/openapi.json",
        "layout": "modern",
        "agent": {"disabled": true}
    });

    Router::<S>::new()
        .route("/openapi.json", get(json))
        .merge(scalar_router("/docs", &configuration).with_state(()))
}

pub fn document() -> OpenApi {
    // Format: method|path|operation id|summary|tag|params|request type|response type.
    // Parameter syntax is name:location, with ! marking a required parameter.
    // Type codes are - (none), t (text), h (HTML), b (binary), j (JSON), or k (bundle).
    const ROUTES: &[&str] = &[
        "get|/openapi.json|openapi_json|Get the OpenAPI document|Documentation||-|j",
        "get|/docs|scalar|Browse the API with Scalar|Documentation||-|h",
        "get|/docs/scalar.js|scalar_asset|Serve the Scalar UI asset|Documentation||-|s",
        "get|/v2/|version|Get registry version|System||-|j",
        "get|/v2|version_bare|Get registry version|System||-|j",
        "get|/v2/_health/{probe}|health|Run a health probe|System|probe:path!|-|t",
        "put|/v2/{namespace}/blobs/{kappa}|put_blob|Store a verified blob|Blobs|namespace:path!,kappa:path!,also:query|b|t",
        "get|/v2/{namespace}/blobs/{kappa}|get_blob|Read a blob|Blobs|namespace:path!,kappa:path!|-|b",
        "head|/v2/{namespace}/blobs/{kappa}|head_blob|Check a blob|Blobs|namespace:path!,kappa:path!|-|t",
        "delete|/v2/{namespace}/blobs/{kappa}|delete_blob|Delete a blob|Blobs|namespace:path!,kappa:path!|-|t",
        "get|/v2/{namespace}/blobs/|list_blobs|List blob labels|Blobs|namespace:path!,prefix:query|-|j",
        "get|/v2/{namespace}/blobs/_meta|list_blobs_by_metadata|List blobs by metadata|Blobs|namespace:path!,key:query!,value:query!|-|j",
        "post|/v2/{namespace}/blobs/uploads/|start_upload|Start or mount a blob upload|Uploads|namespace:path!,mount:query,digest:query|b|t",
        "post|/v2/{namespace}/blobs/uploads|start_upload_bare|Start or mount a blob upload|Uploads|namespace:path!,mount:query,digest:query|b|t",
        "patch|/v2/_uploads/{id}|append_upload|Append an upload chunk|Uploads|id:path!|b|t",
        "get|/v2/_uploads/{id}|inspect_upload|Inspect an upload|Uploads|id:path!|-|t",
        "put|/v2/_uploads/{id}|complete_upload|Complete an upload|Uploads|id:path!,kappa:query!|b|t",
        "delete|/v2/_uploads/{id}|cancel_upload|Cancel an upload|Uploads|id:path!|-|t",
        "put|/v2/{namespace}/manifests/{reference}|put_manifest|Store a manifest and bind its reference|Manifests and tags|namespace:path!,reference:path!|b|t",
        "get|/v2/{namespace}/manifests/{reference}|get_manifest|Read a manifest|Manifests and tags|namespace:path!,reference:path!|-|b",
        "head|/v2/{namespace}/manifests/{reference}|head_manifest|Check a manifest|Manifests and tags|namespace:path!,reference:path!|-|t",
        "delete|/v2/{namespace}/manifests/{reference}|delete_manifest|Delete a manifest reference|Manifests and tags|namespace:path!,reference:path!|-|t",
        "get|/v2/{namespace}/tags/list|list_tags|List namespace tags|Manifests and tags|namespace:path!,n:query,last:query,order:query,after:query,before:query|-|j",
        "get|/v2/{namespace}/tags/{name}|get_tag|Resolve a tag|Manifests and tags|namespace:path!,name:path!,raw:query|-|j",
        "put|/v2/{namespace}/tags/{name}|put_tag|Create or update a tag|Manifests and tags|namespace:path!,name:path!,kappa:query!,symref:query|-|t",
        "post|/v2/{namespace}/tags/_batch|batch_tags|Apply an atomic tag batch|Manifests and tags|namespace:path!|j|j",
        "get|/v2/{namespace}/referrers/{digest}|list_referrers|List OCI referrers|Manifests and tags|namespace:path!,digest:path!,artifactType:query|-|o",
        "put|/v2/{namespace}/edges/|put_edge|Create an edge|Graph|namespace:path!|j|t",
        "put|/v2/{namespace}/edges|put_edge_bare|Create an edge|Graph|namespace:path!|j|t",
        "get|/v2/{namespace}/edges/{node}|query_edges|Query graph edges|Graph|namespace:path!,node:path!,direction:query,relation:query,n:query,last:query|-|j",
        "delete|/v2/{namespace}/edges/{edge_kappa}|delete_edge|Delete an edge|Graph|namespace:path!,edge_kappa:path!|-|t",
        "post|/v2/{namespace}/edges/_diff|diff_edges|Compute an edge diff|Graph|namespace:path!|j|j",
        "post|/v2/{namespace}/_reconcile|reconcile|Exchange reconciliation messages|Replication|namespace:path!|j|j",
        "post|/v2/{namespace}/_bundle/create|create_bundle|Create a Kappa bundle|Bundles|namespace:path!|j|k",
        "post|/v2/{namespace}/_bundle/ingest|ingest_bundle|Ingest a Kappa bundle|Bundles|namespace:path!|k|j",
        "post|/v2/{namespace}/_transaction/begin|begin_transaction|Begin a multi-object transaction|Transactions|namespace:path!|-|j",
        "put|/v2/{namespace}/_transaction/{id}/{kappa}|stage_transaction_blob|Stage a blob in a transaction|Transactions|namespace:path!,id:path!,kappa:path!|b|t",
        "post|/v2/{namespace}/_transaction/{id}/commit|commit_transaction|Commit a transaction|Transactions|namespace:path!,id:path!|-|j",
        "delete|/v2/{namespace}/_transaction/{id}|abort_transaction|Abort a transaction|Transactions|namespace:path!,id:path!|-|t",
        "post|/v2/{namespace}/compose/{operation}|compose|Compose Kappa labels|Composition|namespace:path!,operation:path!|j|j",
        "get|/v2/{namespace}/witnesses/{kappa}|get_witness|Read a composition witness|Composition|namespace:path!,kappa:path!|-|b",
        "put|/v2/{namespace}/schemas/{scope}|put_schema|Register a validation schema|Policies|namespace:path!,scope:path!|b|t",
        "get|/v2/{namespace}/schemas/{scope}|get_schema|Read a validation schema|Policies|namespace:path!,scope:path!|-|b",
        "get|/v2/{namespace}/schemas/|list_schemas|List validation schemas|Policies|namespace:path!|-|j",
        "get|/v2/{namespace}/schemas|list_schemas_bare|List validation schemas|Policies|namespace:path!|-|j",
        "put|/v2/{namespace}/filters/{scope}|put_filter|Register an admission filter|Policies|namespace:path!,scope:path!|b|t",
        "get|/v2/{namespace}/filters/|list_filters|List admission filters|Policies|namespace:path!|-|j",
        "get|/v2/{namespace}/filters|list_filters_bare|List admission filters|Policies|namespace:path!|-|j",
        "delete|/v2/{namespace}/filters/{kappa}|delete_filter|Delete an admission filter|Policies|namespace:path!,kappa:path!|-|t",
        "post|/v2/{namespace}/gc/pin|pin_blob|Pin a blob for garbage collection|Garbage collection|namespace:path!|j|t",
        "post|/v2/{namespace}/gc/unpin|unpin_blob|Release a garbage collection pin|Garbage collection|namespace:path!|j|t",
        "post|/v2/{namespace}/gc/sweep|sweep|Start garbage collection|Garbage collection|namespace:path!|-|j",
        "get|/v2/{namespace}/gc/status|gc_status|Read garbage collection status|Garbage collection|namespace:path!|-|j",
        "get|/v2/{namespace}/_root|namespace_root|Read the namespace root|Namespace proofs|namespace:path!,signed:query|-|j",
        "get|/v2/{namespace}/_root/proof/{name}|namespace_proof|Read a namespace membership proof|Namespace proofs|namespace:path!,name:path!|-|j",
    ];

    let mut paths = Map::new();
    for route in ROUTES {
        let mut fields = route.split('|');
        let method = fields.next().expect("OpenAPI method");
        let path = fields.next().expect("OpenAPI path");
        let id = fields.next().expect("OpenAPI operation id");
        let summary = fields.next().expect("OpenAPI summary");
        let tag = fields.next().expect("OpenAPI tag");
        let params = fields.next().expect("OpenAPI parameters");
        let request = fields.next().and_then(type_code);
        let response = fields.next().and_then(type_code).expect("OpenAPI response");
        let params = params.split(',').filter_map(parameter).collect::<Vec<_>>();
        add(
            &mut paths,
            path,
            method,
            operation(id, summary, tag, &params, request, response),
        );
    }

    serde_json::from_value(json!({
        "openapi": "3.1.0",
        "info": {"title": "kappa-registry API", "version": env!("CARGO_PKG_VERSION"), "description": "Filesystem-backed, single-node Kappa Distribution /v2/ registry. Blobs are addressed by verified Kappa labels and higher-level objects are scoped by namespace."},
        "servers": [{"url": "/"}],
        "tags": [
            {"name": "Documentation"}, {"name": "System"}, {"name": "Blobs"}, {"name": "Uploads"}, {"name": "Manifests and tags"},
            {"name": "Graph"}, {"name": "Replication"}, {"name": "Bundles"}, {"name": "Transactions"},
            {"name": "Composition"}, {"name": "Policies"}, {"name": "Garbage collection"}, {"name": "Namespace proofs"}
        ],
        "paths": paths,
        "components": {"schemas": {"Error": {"type": "object", "properties": {"errors": {"type": "array", "items": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}, "required": ["code", "message"]}}}, "required": ["errors"]}}}
    })).expect("static kappa-registry OpenAPI document is valid")
}

fn type_code(code: &str) -> Option<&'static str> {
    match code {
        "t" => Some("text/plain"),
        "h" => Some("text/html"),
        "b" => Some(BINARY),
        "j" => Some(JSON),
        "k" => Some("application/x-kappa-bundle"),
        "o" => Some("application/vnd.oci.image.index.v1+json"),
        "s" => Some("application/javascript"),
        _ => None,
    }
}

fn parameter(spec: &str) -> Option<Value> {
    let (name, location) = spec.split_once(':')?;
    let (location, required) = location
        .strip_suffix('!')
        .map_or((location, false), |l| (l, true));
    Some(json!({"name": name, "in": location, "required": required, "schema": {"type": "string"}}))
}

fn operation(
    id: &str,
    summary: &str,
    tag: &str,
    params: &[Value],
    request: Option<&str>,
    response: &str,
) -> Value {
    let mut result = json!({"operationId": id, "summary": summary, "tags": [tag], "parameters": params, "responses": {"200": response_value(response), "default": {"description": "Error response", "content": media_type(JSON, json!({"$ref": "#/components/schemas/Error"}))}}});
    if let Some(content_type) = request {
        result["requestBody"] =
            json!({"required": true, "content": media_type(content_type, schema(content_type))});
    }
    result
}

fn response_value(content_type: &str) -> Value {
    let mut value = json!({"description": "Successful response"});
    if content_type != "text/plain" {
        value["content"] = media_type(content_type, schema(content_type));
    }
    value
}

fn schema(content_type: &str) -> Value {
    if content_type == JSON || content_type.ends_with("+json") {
        json!({"type": "object"})
    } else {
        json!({"type": "string", "format": "binary"})
    }
}

fn media_type(content_type: &str, schema: Value) -> Value {
    let mut content = Map::new();
    content.insert(content_type.to_string(), json!({"schema": schema}));
    Value::Object(content)
}

fn add(paths: &mut Map<String, Value>, path: &str, method: &str, operation: Value) {
    paths
        .entry(path.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI path object")
        .insert(method.to_string(), operation);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_has_registry_routes() {
        let value = serde_json::to_value(document()).unwrap();
        assert_eq!(value["openapi"], "3.1.0");
        assert!(value["paths"].as_object().unwrap().len() >= 30);
        assert_eq!(
            value["paths"]["/openapi.json"]["get"]["operationId"],
            "openapi_json"
        );
        assert_eq!(value["paths"]["/docs"]["get"]["operationId"], "scalar");
        assert_eq!(
            value["paths"]["/docs/scalar.js"]["get"]["operationId"],
            "scalar_asset"
        );
        assert!(value["paths"]["/v2/{namespace}/blobs/{kappa}"]["get"].is_object());
        for path in [
            "/v2/{namespace}/blobs/uploads",
            "/v2/{namespace}/edges",
            "/v2/{namespace}/schemas",
            "/v2/{namespace}/filters",
        ] {
            assert!(
                value["paths"][path].is_object(),
                "missing OpenAPI path: {path}"
            );
        }
        assert!(value["components"]["schemas"]["Error"].is_object());
    }
}
