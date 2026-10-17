//! Scalar API reference served by the registry itself.
//!
//! GET /docs           -- Scalar HTML page that renders /openapi.json.
//! GET /docs/scalar.js -- the Scalar standalone bundle embedded in the
//!                        `scalar_api_reference` crate.
//!
//! The page carries no script of its own. The configuration is data in a
//! `<script id="api-reference" type="application/json">` element, which the
//! browser never executes; the standalone bundle reads it on load
//! (`@scalar/api-reference` `standalone/lib/html-api.ts`,
//! `getConfigurationFromDataAttributes`) and mounts the reference beside
//! it. The content security policy therefore admits same-origin scripts
//! only: no inline script, no script digest to keep in step with a template.
//! Default fonts and telemetry are disabled, so nothing loads from a third
//! party.

use http::HeaderValue;
use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, binary_response};

use crate::openapi::DOCUMENT_PATH;

/// Path of the Scalar reference page.
pub const DOCS_PATH: &str = "/docs";
/// Path of the Scalar standalone bundle.
pub const SCALAR_ASSET_PATH: &str = "/docs/scalar.js";
/// Name of the bundle inside the crate's embedded asset folder.
const SCALAR_ASSET: &str = "scalar.js";

/// Policy for the page: scripts only from this registry, styles injected by
/// the bundle, and requests only to this registry.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; \
     font-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Scalar configuration. Keys are defined by `@scalar/types`
/// `apiReferenceConfigurationSchema` and `baseConfigurationSchema`.
fn configuration() -> serde_json::Value {
    serde_json::json!({
        "url": DOCUMENT_PATH,
        "_integration": "rust",
        "withDefaultFonts": false,
        "telemetry": false,
        "agent": {"disabled": true},
    })
}

/// Escape text for a double-quoted HTML attribute value.
fn attribute(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn page() -> String {
    format!(
        "<!doctype html>\n<html>\n  <head>\n    <title>Scalar API Reference</title>\n    \
         <meta charset=\"utf-8\" />\n    \
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  \
         </head>\n  <body>\n    \
         <script id=\"api-reference\" type=\"application/json\" data-configuration=\"{}\"></script>\n    \
         <script src=\"{SCALAR_ASSET_PATH}\"></script>\n  </body>\n</html>\n",
        attribute(&configuration().to_string())
    )
}

// GET /docs. Body: not consumed.
pub async fn page_handler(_cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let mut response = binary_response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        page().into_bytes(),
    )?;
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    Ok(response)
}

// GET /docs/scalar.js. Body: not consumed. The bundle is compiled into the
// binary; its absence is a packaging defect of the dependency.
pub async fn asset_handler(_cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let (mime, content) = scalar_api_reference::get_asset_with_mime(SCALAR_ASSET)
        .ok_or_else(|| HandlerError::internal("scalar_api_reference is missing its scalar.js"))?;
    binary_response(StatusCode::OK, &mime, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The configuration attribute as the browser decodes it.
    fn decoded_configuration(html: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let start = html
            .find("data-configuration=\"")
            .ok_or("page has no configuration attribute")?
            + "data-configuration=\"".len();
        let end = start + html[start..].find('"').ok_or("unterminated attribute")?;
        let decoded = html[start..end]
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        Ok(serde_json::from_str(&decoded)?)
    }

    #[test]
    fn page_loads_bundle_and_document_from_this_registry() -> TestResult {
        let html = page();
        assert!(html.contains("Scalar API Reference"), "{html}");
        assert!(html.contains(SCALAR_ASSET_PATH), "{html}");
        assert!(!html.contains("cdn.jsdelivr.net"), "{html}");
        assert_eq!(decoded_configuration(&html)?, configuration());
        assert_eq!(configuration()["url"], DOCUMENT_PATH);
        Ok(())
    }

    #[test]
    fn page_executes_no_inline_script() {
        let html = page();
        // Exactly two script elements: the non-executed JSON configuration,
        // which precedes the bundle so the bundle finds it on load, and the
        // same-origin bundle.
        let configuration = html.find("<script id=\"api-reference\" type=\"application/json\"");
        let bundle = html.find(&format!("<script src=\"{SCALAR_ASSET_PATH}\"></script>"));
        assert!(configuration.is_some() && bundle.is_some(), "{html}");
        assert!(configuration < bundle, "{html}");
        assert_eq!(html.matches("<script").count(), 2, "{html}");
        assert!(CONTENT_SECURITY_POLICY.contains("script-src 'self';"));
        assert!(!CONTENT_SECURITY_POLICY.contains("sha256-"));
    }

    #[test]
    fn attribute_escaping_cannot_close_the_element() {
        assert_eq!(
            attribute(r#"a"b'c<d>e&f"#),
            "a&quot;b&#39;c&lt;d&gt;e&amp;f"
        );
    }

    #[test]
    fn bundle_is_embedded_as_javascript() -> TestResult {
        let (mime, content) = scalar_api_reference::get_asset_with_mime(SCALAR_ASSET)
            .ok_or("scalar.js not embedded")?;
        assert_eq!(mime, "application/javascript");
        assert!(content.len() > 1_000, "bundle is {} bytes", content.len());
        Ok(())
    }
}
