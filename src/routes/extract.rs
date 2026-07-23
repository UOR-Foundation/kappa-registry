use super::segments;

pub fn split_at<'a>(path: &'a str, segment: &str) -> Option<(&'a str, &'a str)> {
    let inner = path.strip_prefix(segments::PREFIX)?;
    let pos = inner.find(segment)?;
    let ns = &inner[..pos];
    let resource = &inner[pos + segment.len()..];
    Some((ns, resource))
}

pub fn split_at_allow_empty<'a>(path: &'a str, segment: &str) -> Option<(&'a str, &'a str)> {
    let inner = path.strip_prefix(segments::PREFIX)?;
    let pos = inner.find(segment)?;
    let ns = &inner[..pos];
    let rest = &inner[pos + segment.len()..];
    Some((ns, rest))
}

pub fn ns_before_suffix<'a>(path: &'a str, suffix: &str) -> Option<&'a str> {
    let inner = path.strip_prefix(segments::PREFIX)?;
    let trimmed = inner.strip_suffix(suffix)?;
    Some(trimmed)
}

pub fn upload_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix(segments::UPLOADS)?;
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

pub fn health_probe(path: &str) -> Option<&str> {
    let probe = path.strip_prefix(segments::HEALTH)?;
    if matches!(probe, "live" | "ready" | "startup") {
        Some(probe)
    } else {
        None
    }
}
