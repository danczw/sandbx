//! What every test root here starts from. A `common/mod.rs` and not `common.rs`, so Cargo
//! does not build it as a test root of its own.

use sandbx_session_store::SessionStore;

/// A store under a fresh temporary directory.
pub(crate) fn store() -> Store {
    let root = tempfile::tempdir().expect("a temp dir");
    let store = SessionStore::new(root.path().join("sessions"));
    Store { root, store }
}

/// A store, and the directory its root sits in, which has to outlive the store.
pub(crate) struct Store {
    #[allow(
        dead_code,
        reason = "read by permissions.rs; the other roots hold it for its Drop"
    )]
    pub(crate) root: tempfile::TempDir,
    pub(crate) store: SessionStore,
}
