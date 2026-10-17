pub mod absence;
pub mod anchor;
pub mod assert;
pub mod audit;
pub mod resolve;
pub mod revoke;
pub mod watermark;
pub mod whoami;

use topcoat::router::{Method, RouterBuilder};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(identity_route!(
            Method::GET,
            "/identity/whoami",
            whoami::handler
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/assert",
            assert::handler
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/resolve/{subject}",
            resolve::handler
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/revoke",
            revoke::handler
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/watermark",
            watermark::handler
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/absence/{subject}/{*facet}",
            absence::handler
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/audit/{start}/{end}",
            audit::handler
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/anchor",
            anchor::handler
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/binding",
            crate::binding::handlers::put
        ))
        .route(identity_route!(
            Method::DELETE,
            "/identity/binding",
            crate::binding::handlers::delete
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/binding/asserter/{anchor}",
            crate::binding::handlers::list_by_asserter
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/binding/{source}",
            crate::binding::handlers::get
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/succession",
            crate::succession::handlers::put
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/succession/{anchor}/chain",
            crate::succession::handlers::chain
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/succession/{anchor}",
            crate::succession::handlers::resolve
        ))
        .route(identity_route!(
            Method::POST,
            "/identity/handle/claim",
            crate::handle::handlers::claim
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/anchor/{anchor}/handles",
            crate::handle::handlers::by_anchor
        ))
        .route(identity_route!(
            Method::DELETE,
            "/identity/handle/{protocol}/{handle}",
            crate::handle::handlers::delete
        ))
        .route(identity_route!(
            Method::GET,
            "/identity/handle/{protocol}/{handle}",
            crate::handle::handlers::get
        ))
}
