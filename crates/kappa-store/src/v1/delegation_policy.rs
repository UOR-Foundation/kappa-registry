use kappa_types::{DelegationScope, StoreError};

pub fn validate_chain(scopes: &[DelegationScope], now_ms: i64) -> Result<(), StoreError> {
    let mut visited = std::collections::HashSet::new();
    for (index, scope) in scopes.iter().enumerate() {
        if index == 0 {
            visited.insert(scope.delegator.key_bytes());
        }
        if !visited.insert(scope.delegate.key_bytes()) {
            return Err(StoreError::Rejected(
                "delegation chain repeats an anchor".into(),
            ));
        }
        if scope.valid_from_ms > now_ms
            || scope.is_expired(now_ms)
            || scope
                .valid_until_ms
                .is_some_and(|until| until <= scope.valid_from_ms)
        {
            return Err(StoreError::Rejected(
                "delegation validity interval is invalid".into(),
            ));
        }
        if let Some(parent) = index.checked_sub(1).map(|previous| &scopes[previous]) {
            if parent.delegate != scope.delegator {
                return Err(StoreError::Rejected(
                    "delegation chain is disconnected".into(),
                ));
            }
            validate_narrowing(parent, scope)?;
        }
    }
    Ok(())
}

pub fn validate_narrowing(
    parent: &DelegationScope,
    child: &DelegationScope,
) -> Result<(), StoreError> {
    let operations_narrow = child
        .scope
        .iter()
        .all(|operation| parent.permits_operation(operation));
    let namespaces_narrow = parent.namespaces.as_ref().is_none_or(|parents| {
        child.namespaces.as_ref().is_some_and(|children| {
            children
                .iter()
                .all(|child| parents.iter().any(|parent| child.starts_with(parent)))
        })
    });
    let interval_narrows = child.valid_from_ms >= parent.valid_from_ms
        && parent.valid_until_ms.is_none_or(|parent_until| {
            child
                .valid_until_ms
                .is_some_and(|until| until <= parent_until)
        });
    if child.max_depth >= parent.max_depth
        || !operations_narrow
        || !namespaces_narrow
        || !interval_narrows
    {
        return Err(StoreError::Rejected(
            "delegation broadens parent authority".into(),
        ));
    }
    Ok(())
}
