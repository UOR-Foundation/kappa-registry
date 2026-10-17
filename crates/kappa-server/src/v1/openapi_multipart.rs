use serde_json::{Map, Value, json};

pub(super) fn apply(paths: &mut Map<String, Value>) {
    let query_paths: Vec<_> = paths
        .keys()
        .filter(|path| path.contains('?'))
        .cloned()
        .collect();
    for query_path in query_paths {
        let Some((path, selector)) = query_path.split_once('?') else {
            continue;
        };
        let Some(operations) = paths.remove(&query_path) else {
            continue;
        };
        let Some(operations) = operations.as_object() else {
            continue;
        };
        for (method, original) in operations {
            let mut operation = original.clone();
            if let Some(parameters) = operation["parameters"].as_array_mut() {
                for name in selector.split('&') {
                    if name == "copy" {
                        continue;
                    }
                    if !parameters.iter().any(|parameter| parameter["name"] == name) {
                        parameters.push(json!({"name": name, "in": "query", "required": true, "allowEmptyValue": true, "schema": {"type": "string"}}));
                    }
                }
            }
            let id = operation["operationId"].as_str().unwrap_or("").to_owned();
            if id.starts_with("s3_") {
                operation["responses"]["default"] = json!({"description": "S3 error", "content": {"application/xml": {"schema": {"type": "string"}}}});
            }
            match id.as_str() {
                "s3_upload_part" => {
                    operation["description"] = json!(
                        "Numbered parts may arrive out of order. Re-uploading a part number atomically replaces its bytes and ETag. The upload ID is bound to the bucket and object key."
                    );
                    operation["responses"]["200"] = json!({"description": "Part stored", "headers": {"ETag": {"description": "Quoted MD5 of this part", "schema": {"type": "string"}}}});
                    if let Some(parameters) = operation["parameters"].as_array_mut() {
                        for parameter in parameters {
                            if parameter["name"] == "partNumber" {
                                parameter["schema"] =
                                    json!({"type": "integer", "minimum": 1, "maximum": 10000});
                            }
                        }
                    }
                }
                "s3_complete_multipart" => {
                    operation["description"] = json!(
                        "Complete exactly the selected parts in ascending part-number order. Each ETag must match the current uploaded part. Nonfinal selected parts must be at least 5 MiB. Invalid selection leaves the upload available for correction."
                    );
                    operation["requestBody"] = json!({"required": true, "content": {"application/xml": {"schema": {"type": "object", "xml": {"name": "CompleteMultipartUpload"}, "required": ["Part"], "properties": {"Part": {"type": "array", "minItems": 1, "maxItems": 10000, "items": {"type": "object", "xml": {"name": "Part"}, "required": ["PartNumber", "ETag"], "properties": {"PartNumber": {"type": "integer", "minimum": 1, "maximum": 10000}, "ETag": {"type": "string"}}}}}}}}});
                    operation["responses"]["200"] = json!({"description": "Selected parts published", "content": {"application/xml": {"schema": {"type": "string"}}}});
                }
                "s3_list_parts" => {
                    operation["description"] = json!(
                        "List current numbered parts in numeric order. max-parts is bounded to 1000; part-number-marker is exclusive. NextPartNumberMarker resumes a truncated response."
                    );
                    if let Some(parameters) = operation["parameters"].as_array_mut() {
                        parameters.extend([
                            json!({"name": "max-parts", "in": "query", "schema": {"type": "integer", "minimum": 0, "maximum": 1000, "default": 1000}}),
                            json!({"name": "part-number-marker", "in": "query", "schema": {"type": "integer", "minimum": 0, "maximum": 10000}}),
                        ]);
                    }
                    operation["responses"]["200"] = json!({"description": "Current part receipts", "content": {"application/xml": {"schema": {"type": "string"}}}});
                }
                "s3_create_multipart" => {
                    operation["responses"]["200"] = json!({"description": "Upload initiated", "content": {"application/xml": {"schema": {"type": "string"}}}})
                }
                "s3_abort_multipart" => {
                    if let Some(responses) = operation["responses"].as_object_mut() {
                        responses.remove("200");
                    }
                    operation["responses"]["204"] =
                        json!({"description": "Upload staging removed"});
                }
                _ => {}
            }
            let methods = paths.entry(path.to_owned()).or_insert_with(|| json!({}));
            if methods.get(method).is_none() {
                methods[method] = json!({"operationId": format!("s3_dispatch_{method}_{}", if path.ends_with("{key}") { "object" } else { "bucket" }), "summary": "Query-dispatched S3 operation", "tags": ["S3"], "responses": {"200": {"description": "Success"}}});
            }
            if let Some(parameters) = operation["parameters"].as_array() {
                if !methods[method]["parameters"].is_array() {
                    methods[method]["parameters"] = json!([]);
                }
                if let Some(merged) = methods[method]["parameters"].as_array_mut() {
                    for parameter in parameters {
                        if !merged.iter().any(|existing| {
                            existing["name"] == parameter["name"]
                                && existing["in"] == parameter["in"]
                        }) {
                            let mut parameter = parameter.clone();
                            if parameter["in"] == "query" {
                                parameter["required"] = json!(false);
                            }
                            merged.push(parameter);
                        }
                    }
                }
            }
            if let Some(content) = operation["requestBody"]["content"].as_object() {
                for (media, schema) in content {
                    methods[method]["requestBody"]["content"][media] = schema.clone();
                }
                if method == "post" {
                    methods[method]["requestBody"]["required"] = json!(false);
                }
            }
            if let Some(responses) = operation["responses"].as_object() {
                for (status, response) in responses {
                    if methods[method]["responses"].get(status).is_none() {
                        methods[method]["responses"][status] = response.clone();
                    } else {
                        for field in ["content", "headers"] {
                            if let Some(values) = response[field].as_object() {
                                for (name, value) in values {
                                    methods[method]["responses"][status][field][name] =
                                        value.clone();
                                }
                            }
                        }
                    }
                }
            }
            methods[method]["description"] = json!(
                "S3 query dispatch uses the optional selector parameters. x-query-operations specifies the request, response, and validation contract for each selector. Object keys may contain slashes."
            );
            methods[method]["x-query-operations"][selector] = operation;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn multipart_document_uses_runtime_paths_and_actual_media() {
        let document = super::super::document();
        let paths = document["paths"].as_object().expect("paths");
        assert!(paths.keys().all(|path| !path.contains('?')));
        let completion = &paths["/{bucket}/{key}"]["post"]["x-query-operations"]["uploadId"];
        assert!(completion["requestBody"]["content"]["application/xml"].is_object());
        let upload = &paths["/{bucket}/{key}"]["put"]["x-query-operations"]["partNumber&uploadId"];
        assert!(upload["responses"]["200"]["headers"]["ETag"].is_object());
        let list = &paths["/{bucket}/{key}"]["get"]["x-query-operations"]["uploadId"];
        assert!(
            list["parameters"]
                .as_array()
                .expect("parameters")
                .iter()
                .any(|parameter| parameter["name"] == "part-number-marker")
        );
    }
}
