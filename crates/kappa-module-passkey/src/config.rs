//! Identity origins: the pages allowed to run the WebAuthn ceremony.
//!
//! A passkey belongs to one relying party ID (rpId), and every page on that
//! rpId's origin can ask it to sign. So the registry accepts ceremony output
//! only from the origins the operator lists, and binds each to its host as
//! the rpId. Parsed from `KAPPA_PASSKEY_ORIGINS`, comma separated.

use kappa_core::kappa::sha256_raw;

/// One accepted identity origin and the relying party it implies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityOrigin {
    /// Serialized origin as browsers write it in clientDataJSON.
    pub origin: String,
    /// The origin's host, used as the WebAuthn rpId.
    pub rp_id: String,
    /// SHA-256 of `rp_id`, the first 32 bytes of authenticator data.
    pub rp_hash: [u8; 32],
}

/// The set of identity origins this registry accepts.
#[derive(Debug, Clone, Default)]
pub struct PasskeyConfig {
    origins: Vec<IdentityOrigin>,
}

impl PasskeyConfig {
    /// Parse a comma-separated origin list. Each entry is `https://host[:port]`,
    /// or `http://localhost[:port]` for development, which WebAuthn treats as
    /// a secure context. Paths, credentials, queries and IPv6 literals are
    /// refused so an origin always compares equal to the browser's.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut origins = Vec::new();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let origin = parse_origin(entry)?;
            if !origins
                .iter()
                .any(|o: &IdentityOrigin| o.origin == origin.origin)
            {
                origins.push(origin);
            }
        }
        Ok(Self { origins })
    }

    /// The accepted origin equal to `origin`, if any.
    pub fn origin(&self, origin: &str) -> Option<&IdentityOrigin> {
        self.origins.iter().find(|o| o.origin == origin)
    }

    /// True when `origin` is an accepted identity origin.
    pub fn allows(&self, origin: &str) -> bool {
        self.origin(origin).is_some()
    }

    /// Every accepted origin, in configured order.
    pub fn origins(&self) -> &[IdentityOrigin] {
        &self.origins
    }
}

fn parse_origin(entry: &str) -> Result<IdentityOrigin, String> {
    let lowered = entry.to_ascii_lowercase();
    let trimmed = lowered.strip_suffix('/').unwrap_or(&lowered);
    let (scheme, authority) = trimmed
        .split_once("://")
        .ok_or_else(|| format!("{entry}: an origin is scheme://host[:port]"))?;
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', '[', ']']) {
        return Err(format!(
            "{entry}: an origin has no path, query, credentials or IPv6 literal"
        ));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || port.len() > 5 {
            return Err(format!("{entry}: the port must be a number"));
        }
    }
    let valid_host = !host.is_empty()
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !valid_host {
        return Err(format!("{entry}: the host must be a domain name"));
    }
    match scheme {
        "https" => {}
        "http" if host == "localhost" => {}
        "http" => {
            return Err(format!(
                "{entry}: plain http is accepted only for localhost"
            ))
        }
        _ => return Err(format!("{entry}: the scheme must be https")),
    }
    Ok(IdentityOrigin {
        origin: trimmed.to_string(),
        rp_id: host.to_string(),
        rp_hash: sha256_raw(host.as_bytes()),
    })
}
