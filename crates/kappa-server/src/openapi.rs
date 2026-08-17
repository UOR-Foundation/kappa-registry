//! OpenAPI 3.1 spec and Scalar documentation UI.
//!
//! GET /openapi.json -- OpenAPI 3.1 document as JSON.
//! GET /docs         -- Scalar API reference UI (loads from CDN).
//!
//! The spec is built from a route catalog co-located in this file.
//! When a route is added to any module, add a matching entry here.

use topcoat::context::Cx;
use topcoat::router::response::IntoResponse;
use topcoat::router::{Body, RouteFuture, StatusCode};

use serde_json::{json, Map, Value};

// -- Route catalog ------------------------------------------------------------
// Format: "method|path|operation_id|summary|tag|params|request_type|response_type"
//
// Parameter syntax: name:location with ! marking required.
// Type codes: - (none), t (text), b (binary), j (JSON), k (bundle),
//             o (OCI index), e (event-stream).

const ROUTES: &[&str] = &[
    // System
    "get|/_status|status|Server status|System||-|t",
    "get|/v2/|version|Registry version check|System||-|j",
    "get|/v2/_health/{probe}|health|Health probe|System|probe:path!|-|t",
    // OpenAPI
    "get|/openapi.json|openapi_json|OpenAPI document|Documentation||-|j",
    "get|/docs|docs|Scalar API reference|Documentation||-|t",
    // Blobs
    "put|/v2/{namespace}/blobs/{kappa}|put_blob|Store a verified blob|Blobs|namespace:path!,kappa:path!,also:query|b|t",
    "get|/v2/{namespace}/blobs/{kappa}|get_blob|Read a blob|Blobs|namespace:path!,kappa:path!|-|b",
    "head|/v2/{namespace}/blobs/{kappa}|head_blob|Check a blob|Blobs|namespace:path!,kappa:path!|-|t",
    "delete|/v2/{namespace}/blobs/{kappa}|delete_blob|Delete a blob|Blobs|namespace:path!,kappa:path!|-|t",
    "get|/v2/{namespace}/blobs/|list_blobs|List blob labels|Blobs|namespace:path!,prefix:query|-|j",
    "get|/v2/{namespace}/blobs/_meta|list_by_meta|List blobs by metadata|Blobs|namespace:path!,key:query!,value:query!|-|j",
    "post|/v2/{namespace}/blobs/_cascade|cascade_delete|Cascade delete|Blobs|namespace:path!|j|j",
    // Uploads
    "post|/v2/{namespace}/blobs/uploads/|start_upload|Start or mount a blob upload|Uploads|namespace:path!,mount:query,digest:query|b|t",
    "patch|/v2/_uploads/{id}|append_chunk|Append an upload chunk|Uploads|id:path!|b|t",
    "put|/v2/_uploads/{id}|complete_upload|Complete an upload|Uploads|id:path!,digest:query!|b|t",
    "get|/v2/_uploads/{id}|inspect_upload|Inspect an upload|Uploads|id:path!|-|t",
    "delete|/v2/_uploads/{id}|cancel_upload|Cancel an upload|Uploads|id:path!|-|t",
    // Manifests and tags
    "put|/v2/{namespace}/manifests/{reference}|put_manifest|Store a manifest|Manifests|namespace:path!,reference:path!,tag:query|b|t",
    "get|/v2/{namespace}/manifests/{reference}|get_manifest|Read a manifest|Manifests|namespace:path!,reference:path!|-|b",
    "head|/v2/{namespace}/manifests/{reference}|head_manifest|Check a manifest|Manifests|namespace:path!,reference:path!|-|t",
    "delete|/v2/{namespace}/manifests/{reference}|delete_manifest|Delete a manifest|Manifests|namespace:path!,reference:path!|-|t",
    "get|/v2/{namespace}/tags/list|list_tags|List namespace tags|Tags|namespace:path!,n:query,last:query,order:query,after:query,before:query|-|j",
    "post|/v2/{namespace}/tags/_batch|batch_tags|Atomic tag batch|Tags|namespace:path!|j|j",
    "delete|/v2/{namespace}/tags/_prefix|delete_tag_prefix|Delete tags by prefix|Tags|namespace:path!,prefix:query!|-|t",
    "post|/v2/{namespace}/tags/|tag_crud_post|Create a tag|Tags|namespace:path!|j|j",
    "get|/v2/{namespace}/tags/|tag_crud_get|Get a tag by query|Tags|namespace:path!,name:query!|-|j",
    "delete|/v2/{namespace}/tags/|tag_crud_delete|Delete a tag by query|Tags|namespace:path!,name:query!|-|t",
    "get|/v2/{namespace}/tags/{name}|get_tag|Resolve a tag|Tags|namespace:path!,name:path!|-|j",
    "put|/v2/{namespace}/tags/{name}|put_tag|Create or update a tag|Tags|namespace:path!,name:path!,kappa:query!|-|t",
    "get|/v2/{namespace}/referrers/{digest}|list_referrers|List OCI referrers|Tags|namespace:path!,digest:path!,artifactType:query|-|j",
    // Graph
    "put|/v2/{namespace}/edges/|put_edge|Create an edge|Graph|namespace:path!|j|t",
    "get|/v2/{namespace}/edges/{edge_key}|query_edges|Query graph edges|Graph|namespace:path!,edge_key:path!,direction:query,relation:query|-|j",
    "delete|/v2/{namespace}/edges/{edge_key}|delete_edge|Delete an edge|Graph|namespace:path!,edge_key:path!|-|t",
    "post|/v2/{namespace}/edges/_diff|diff_edges|Compute edge diff|Graph|namespace:path!|j|j",
    // Composition
    "post|/v2/{namespace}/compose/{op}|compose|Compose kappa labels|Composition|namespace:path!,op:path!|j|j",
    "get|/v2/{namespace}/witnesses/{kappa}|get_witness|Read a composition witness|Composition|namespace:path!,kappa:path!|-|b",
    // Bundles
    "post|/v2/{namespace}/_bundle/create|create_bundle|Create a kappa bundle|Bundles|namespace:path!|j|k",
    "post|/v2/{namespace}/_bundle/ingest|ingest_bundle|Ingest a kappa bundle|Bundles|namespace:path!|k|j",
    // Policies
    "put|/v2/{namespace}/filters/{filter_key}|put_filter|Register an admission filter|Policies|namespace:path!,filter_key:path!|b|t",
    "get|/v2/{namespace}/filters/|list_filters|List admission filters|Policies|namespace:path!|-|j",
    "delete|/v2/{namespace}/filters/{filter_key}|delete_filter|Delete an admission filter|Policies|namespace:path!,filter_key:path!|-|t",
    "put|/v2/{namespace}/schemas/{scope}|put_schema|Register a validation schema|Policies|namespace:path!,scope:path!|b|t",
    "get|/v2/{namespace}/schemas/{scope}|get_schema|Read a validation schema|Policies|namespace:path!,scope:path!|-|b",
    "get|/v2/{namespace}/schemas/|list_schemas|List validation schemas|Policies|namespace:path!|-|j",
    // Garbage collection
    "post|/v2/{namespace}/gc/pin|pin_blob|Pin a blob|GC|namespace:path!|j|t",
    "post|/v2/{namespace}/gc/unpin|unpin_blob|Unpin a blob|GC|namespace:path!|j|t",
    "post|/v2/{namespace}/gc/sweep|sweep|Run garbage collection|GC|namespace:path!|-|j",
    "get|/v2/{namespace}/gc/status|gc_status|GC status|GC|namespace:path!|-|j",
    // Transactions
    "post|/v2/{namespace}/_transaction/begin|begin_txn|Begin a transaction|Transactions|namespace:path!|-|j",
    "put|/v2/{namespace}/_transaction/{id}/{kappa}|stage_blob|Stage a blob in a transaction|Transactions|namespace:path!,id:path!,kappa:path!|b|t",
    "post|/v2/{namespace}/_transaction/{id}/commit|commit_txn|Commit a transaction|Transactions|namespace:path!,id:path!|-|j",
    "delete|/v2/{namespace}/_transaction/{id}|abort_txn|Abort a transaction|Transactions|namespace:path!,id:path!|-|t",
    // Sequences
    "post|/v2/{namespace}/_sequence/{name}/next|sequence_next|Advance a sequence|Sequences|namespace:path!,name:path!|-|j",
    "get|/v2/{namespace}/_sequence/{name}|sequence_current|Read a sequence|Sequences|namespace:path!,name:path!|-|j",
    // Namespace proofs
    "get|/v2/{namespace}/_root|namespace_root|Read namespace root|Namespace|namespace:path!,signed:query|-|j",
    "get|/v2/{namespace}/_root/proof/{name}|namespace_proof|Read membership proof|Namespace|namespace:path!,name:path!|-|j",
    // Reconciliation
    "post|/v2/{namespace}/_reconcile|reconcile|Exchange reconciliation messages|Replication|namespace:path!|j|j",
    // Events
    "get|/v2/{namespace}/_events|events_sse|SSE event stream|Events|namespace:path!|-|e",
    "get|/v2/{namespace}/_events/_ws|events_ws|WebSocket event stream|Events|namespace:path!|-|t",
    "get|/v2/{namespace}/_crdt/{doc}/_ws|crdt_ws|CRDT collaboration WebSocket|Events|namespace:path!,doc:path!|-|t",
    // Identity
    "get|/identity/whoami|identity_whoami|Node identity|Identity||-|j",
    "post|/identity/assert|identity_assert|Publish an assertion|Identity||j|j",
    "get|/identity/resolve/{subject}|identity_resolve|Resolve assertions|Identity|subject:path!|-|j",
    "post|/identity/revoke|identity_revoke|Revoke an assertion|Identity||j|j",
    "get|/identity/absence/{subject}/{facet}|identity_absence|Absence proof|Identity|subject:path!,facet:path!|-|j",
    "get|/identity/audit/{start}/{end}|identity_audit|Audit proof|Identity|start:path!,end:path!|-|j",
    "post|/identity/watermark|identity_watermark|Advance watermark|Identity||j|j",
    "post|/identity/anchor|identity_anchor|Register anchor spec|Identity||j|j",
    "post|/identity/binding|identity_binding_put|Create identity binding|Identity||j|j",
    "delete|/identity/binding|identity_binding_delete|Delete identity binding|Identity||j|-",
    "get|/identity/binding/asserter/{anchor}|identity_binding_list_by_asserter|List bindings by asserter|Identity|anchor:path!|-|j",
    "get|/identity/binding/{source}|identity_binding_get|List bindings for identifier|Identity|source:path!|-|j",
    "post|/identity/succession|identity_succession_put|Create identity succession|Identity||j|j",
    "get|/identity/succession/{anchor}/chain|identity_succession_chain|Full succession chain|Identity|anchor:path!|-|j",
    "get|/identity/succession/{anchor}|identity_succession_resolve|Resolve to current anchor|Identity|anchor:path!|-|j",
    // Cluster
    "get|/cluster/members|cluster_members|List cluster members|System||-|j",
    "get|/cluster/status|cluster_status|Cluster status|System||-|j",
    // Git smart HTTP
    "get|/{repo}.git/info/refs|git_info_refs|Git ref advertisement|Git|repo:path!,service:query!|-|t",
    "post|/{repo}.git/git-upload-pack|git_upload_pack|Git fetch/clone (upload-pack)|Git|repo:path!|b|b",
    "post|/{repo}.git/git-receive-pack|git_receive_pack|Git push (receive-pack)|Git|repo:path!|b|b",
    // S3-compatible API
    "get|/|s3_list_buckets|List S3 buckets|S3||-|t",
    "put|/{bucket}|s3_create_bucket|Create S3 bucket|S3|bucket:path!|-|t",
    "delete|/{bucket}|s3_delete_bucket|Delete S3 bucket|S3|bucket:path!|-|t",
    "get|/{bucket}|s3_list_objects|List objects (ListObjectsV2)|S3|bucket:path!,prefix:query,delimiter:query,max-keys:query,continuation-token:query,start-after:query,encoding-type:query|-|t",
    "head|/{bucket}|s3_head_bucket|Check bucket existence|S3|bucket:path!|-|t",
    "put|/{bucket}/{key}|s3_put_object|Upload object|S3|bucket:path!,key:path!|b|t",
    "get|/{bucket}/{key}|s3_get_object|Download object|S3|bucket:path!,key:path!|-|b",
    "head|/{bucket}/{key}|s3_head_object|Object metadata|S3|bucket:path!,key:path!|-|t",
    "delete|/{bucket}/{key}|s3_delete_object|Delete object|S3|bucket:path!,key:path!|-|t",
    "post|/{bucket}?delete|s3_delete_objects|Batch delete objects|S3|bucket:path!|t|t",
    "post|/{bucket}/{key}?uploads|s3_create_multipart|Initiate multipart upload|S3|bucket:path!,key:path!|-|t",
    "put|/{bucket}/{key}?partNumber&uploadId|s3_upload_part|Upload part|S3|bucket:path!,key:path!,partNumber:query!,uploadId:query!|b|t",
    "post|/{bucket}/{key}?uploadId|s3_complete_multipart|Complete multipart upload|S3|bucket:path!,key:path!,uploadId:query!|t|t",
    "delete|/{bucket}/{key}?uploadId|s3_abort_multipart|Abort multipart upload|S3|bucket:path!,key:path!,uploadId:query!|-|t",
    "get|/{bucket}/{key}?uploadId|s3_list_parts|List parts|S3|bucket:path!,key:path!,uploadId:query!|-|t",
    "put|/{bucket}/{key}?copy|s3_copy_object|Copy object|S3|bucket:path!,key:path!|-|t",
    "get|/{bucket}/{key}?attributes|s3_get_object_attributes|Object attributes|S3|bucket:path!,key:path!|-|t",
];

// -- Spec builder -------------------------------------------------------------

fn document() -> Value {
    let mut paths = Map::new();
    for entry in ROUTES {
        let mut fields = entry.split('|');
        let method = fields.next().unwrap_or("");
        let path = fields.next().unwrap_or("");
        let op_id = fields.next().unwrap_or("");
        let summary = fields.next().unwrap_or("");
        let tag = fields.next().unwrap_or("");
        let params_str = fields.next().unwrap_or("");
        let req_type = fields.next().and_then(type_code);
        let resp_type = fields.next().and_then(type_code).unwrap_or("text/plain");

        let params: Vec<Value> = params_str
            .split(',')
            .filter_map(parse_parameter)
            .collect();

        let mut op = json!({
            "operationId": op_id,
            "summary": summary,
            "tags": [tag],
            "parameters": params,
            "responses": {
                "200": response_obj(resp_type),
                "default": {
                    "description": "Error",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    }
                }
            }
        });

        if let Some(ct) = req_type {
            op["requestBody"] = json!({
                "required": true,
                "content": {
                    ct: {"schema": schema_for(ct)}
                }
            });
        }

        // Convert {*ns} catch-all to {namespace} for OpenAPI display
        let display_path = path
            .replace("{*ns}", "{namespace}")
            .replace("{*facet}", "{facet}")
            .replace("{*rest}", "{rest}");

        paths
            .entry(display_path)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .unwrap()
            .insert(method.to_string(), op);
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "kappa-registry",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Content-addressed object registry implementing the OCI distribution spec v1.1 and the kappa-distribution protocol."
        },
        "servers": [{"url": "/"}],
        "tags": [
            {"name": "System"},
            {"name": "Documentation"},
            {"name": "Blobs"},
            {"name": "Uploads"},
            {"name": "Manifests"},
            {"name": "Tags"},
            {"name": "Graph"},
            {"name": "Composition"},
            {"name": "Bundles"},
            {"name": "Policies"},
            {"name": "GC"},
            {"name": "Transactions"},
            {"name": "Sequences"},
            {"name": "Namespace"},
            {"name": "Replication"},
            {"name": "Events"},
            {"name": "Identity"}
        ],
        "paths": paths,
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "code": {"type": "string"},
                                    "message": {"type": "string"}
                                },
                                "required": ["code", "message"]
                            }
                        }
                    },
                    "required": ["errors"]
                }
            }
        }
    })
}

fn type_code(code: &str) -> Option<&'static str> {
    match code {
        "t" => Some("text/plain"),
        "b" => Some("application/octet-stream"),
        "j" => Some("application/json"),
        "k" => Some("application/x-kappa-bundle"),
        "o" => Some("application/vnd.oci.image.index.v1+json"),
        "e" => Some("text/event-stream"),
        "-" => None,
        _ => None,
    }
}

fn parse_parameter(spec: &str) -> Option<Value> {
    let (name, location) = spec.split_once(':')?;
    let (location, required) = location
        .strip_suffix('!')
        .map_or((location, false), |l| (l, true));
    Some(json!({
        "name": name,
        "in": location,
        "required": required,
        "schema": {"type": "string"}
    }))
}

fn response_obj(content_type: &str) -> Value {
    if content_type == "text/plain" {
        json!({"description": "Success"})
    } else {
        json!({
            "description": "Success",
            "content": {
                content_type: {"schema": schema_for(content_type)}
            }
        })
    }
}

fn schema_for(content_type: &str) -> Value {
    if content_type.contains("json") {
        json!({"type": "object"})
    } else {
        json!({"type": "string", "format": "binary"})
    }
}

// -- Scalar HTML template -----------------------------------------------------

const SCALAR_HTML: &str = r#"<!doctype html>
<html>
<head>
    <title>kappa-registry API</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
</head>
<body>
<script id="api-reference" type="application/json">
$spec
</script>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>"#;

// -- Handlers -----------------------------------------------------------------

pub fn openapi_json_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let spec = document();
        let json = serde_json::to_string_pretty(&spec).unwrap_or_default();
        (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            json,
        )
            .into_response(cx)
    })
}

pub fn docs_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let spec = document();
        let spec_json = serde_json::to_string(&spec).unwrap_or_default();
        let html = SCALAR_HTML.replace("$spec", &spec_json);
        (
            StatusCode::OK,
            [
                ("content-type", "text/html; charset=utf-8".to_string()),
                (
                    "content-security-policy",
                    "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'; img-src 'self' data:; font-src https://cdn.jsdelivr.net".to_string(),
                ),
            ],
            html,
        )
            .into_response(cx)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_has_openapi_version() {
        let doc = document();
        assert_eq!(doc["openapi"], "3.1.0");
    }

    #[test]
    fn document_has_paths() {
        let doc = document();
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.len() >= 50, "expected >= 50 paths, got {}", paths.len());
    }

    #[test]
    fn document_has_error_schema() {
        let doc = document();
        assert!(doc["components"]["schemas"]["Error"].is_object());
    }

    #[test]
    fn every_route_entry_parses() {
        for entry in ROUTES {
            let fields: Vec<&str> = entry.split('|').collect();
            assert_eq!(
                fields.len(),
                8,
                "route entry has wrong field count: {}",
                entry
            );
            let method = fields[0];
            assert!(
                ["get", "head", "put", "post", "delete", "patch"].contains(&method),
                "invalid method in route entry: {}",
                entry
            );
        }
    }

    #[test]
    fn scalar_html_contains_spec_placeholder() {
        assert!(SCALAR_HTML.contains("$spec"));
    }

    #[test]
    fn known_routes_present() {
        let doc = document();
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/v2/{namespace}/blobs/{kappa}"));
        assert!(paths.contains_key("/v2/{namespace}/manifests/{reference}"));
        assert!(paths.contains_key("/v2/{namespace}/tags/list"));
        assert!(paths.contains_key("/identity/whoami"));
        assert!(paths.contains_key("/openapi.json"));
        assert!(paths.contains_key("/docs"));
    }
}
