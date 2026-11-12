//! Reads observed through a memory execution, including its private writes:
//! every namespace-local read is decided by the candidate view; handles and
//! authorization rows held by other namespaces are read from their
//! published views, and authorization reads record their dependency.

use kappa_store::traits::identity::CredentialLookup;
use kappa_store::{
    ClockMs, Edge, EdgeQuery, ExecutionReads, Kappa, NamespaceInfo, NamespaceRef, Page,
    PageRequest, StoreError, TagEntry, identity::HandleRecord, namespace::ProtocolId,
};

use super::blob_read;
use super::edge::edge_query_in;
use super::execution::MemoryExecution;
use super::namespace_write::{namespace_get_meta_in, namespace_info_in};
use super::sequence::sequence_current_in;
use super::tag::{tag_get_in, tag_get_raw_in};

impl ExecutionReads for MemoryExecution<'_> {
    fn namespace(&self) -> &NamespaceRef {
        self.namespace_ref()
    }

    fn now(&self) -> ClockMs {
        self.issued_at()
    }

    fn tag_get(&self, name: &str) -> Result<Option<TagEntry>, StoreError> {
        self.lookup(|cx| tag_get_in(cx.view, cx.ns, name))
    }

    fn tag_get_raw(&self, name: &str) -> Result<Option<TagEntry>, StoreError> {
        self.lookup(|cx| tag_get_raw_in(cx.view, cx.ns, name))
    }

    fn namespace_info(&self) -> Result<Option<NamespaceInfo>, StoreError> {
        self.lookup(|cx| namespace_info_in(cx.view, cx.ns))
    }

    fn sequence_current(&self, name: &str) -> Result<u64, StoreError> {
        self.read(|cx| Ok(sequence_current_in(cx.view, name)))
    }

    fn namespace_get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.lookup(|cx| namespace_get_meta_in(cx.view, cx.ns, key))
    }

    fn blob_meta_get(&self, identity: &Kappa, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.read(|cx| {
            Ok(cx
                .view
                .blob_meta
                .get(&(identity.clone(), key.to_owned()))
                .cloned())
        })
    }

    /// Read and verified on the execution's allowance.
    fn blob_get_verified(
        &self,
        identity: &Kappa,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.lookup(|cx| {
            self.lend(|meter| {
                Ok(
                    blob_read::verified(cx.view, identity, Some(maximum), meter)?
                        .into_parts()
                        .1,
                )
            })
        })
    }

    fn handle_get(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Result<Option<HandleRecord>, StoreError> {
        self.read(|cx| Ok(cx.handle(protocol, handle)))
    }

    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        self.read(|cx| cx.handles_by_anchor(anchor, page))
    }

    fn edge_query(&self, query: &EdgeQuery, page: &PageRequest) -> Result<Page<Edge>, StoreError> {
        self.read(|cx| edge_query_in(cx.view, query, page))
    }

    /// The dependency is the row as observed, expired or not; expiry is
    /// decided against the execution's time, and a live session's expiry
    /// again against the time its publication is installed at.
    fn session_get(&self, token: &str) -> Result<Option<(Kappa, Vec<u8>)>, StoreError> {
        self.read(|cx| Ok(cx.live_session(token)))
    }

    fn credential_get(&self, credential_id: &str) -> Result<Option<CredentialLookup>, StoreError> {
        self.read(|cx| Ok(cx.credential_row(credential_id)))
    }
}
