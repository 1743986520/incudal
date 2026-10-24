//! TODO(port): instances.ts route family (wave C) — fills this in. Until then
//! only the snapshots router (same /api/instances prefix upstream) is live.

use axum::Router;

use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    crate::routes::not_ported_router().merge(crate::routes::snapshots::router())
}
