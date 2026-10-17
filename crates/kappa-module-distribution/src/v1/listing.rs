use kappa_store::{NamespaceRef, PageRequest, StoreError, TagEntry, TagStore};

pub(crate) fn tags(
    store: &dyn TagStore,
    namespace: &NamespaceRef,
    prefix: Option<&str>,
) -> Result<Vec<TagEntry>, StoreError> {
    let mut request = PageRequest::first(1024);
    let mut result = Vec::new();
    loop {
        let page = store.tag_list(namespace, prefix, &request)?;
        result.extend(page.items);
        let Some(next) = page.next_after else {
            return Ok(result);
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| previous >= &next)
        {
            return Err(StoreError::Internal(
                "tag pagination did not advance".into(),
            ));
        }
        request.after = Some(next);
    }
}
