//! Instance-task execution guard.
//! Port of lib/incus/incus-execution-guard.ts.
//!
//! The TS version uses `AsyncLocalStorage` so each worker task can carry its
//! own guard; all Incus calls check the ambient guard and attach its
//! `AbortSignal`. The Rust port uses `tokio::task_local!` for the ambient
//! context and an `Arc<IncusExecutionGuard>` flag/reason pair for the signal.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::libs::incus::incus_client::IncusError;

pub const DEFAULT_ABORT_REASON: &str = "Instance task execution lease is no longer owned";

/// Mirrors `IncusExecutionGuard { signal, assertActive() }`. Aborting stores a
/// reason so later stages fail with the original cause (the TS aborts the
/// signal with an Error reason).
pub struct IncusExecutionGuard {
    aborted: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl Default for IncusExecutionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl IncusExecutionGuard {
    pub fn new() -> Self {
        Self {
            aborted: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }

    /// Abort the guard with a reason (TS: controller.abort(reason)).
    pub fn abort(&self, reason: impl Into<String>) {
        let mut slot = self.reason.lock().expect("guard reason mutex poisoned");
        if slot.is_none() {
            *slot = Some(reason.into());
        }
        self.aborted.store(true, Ordering::SeqCst);
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    /// The reason the guard was aborted with, if any.
    pub fn abort_reason(&self) -> Option<String> {
        self.reason
            .lock()
            .expect("guard reason mutex poisoned")
            .clone()
    }

    /// Mirrors `guard.assertActive()` — resolves while the lease is held,
    /// rejects with the abort reason once the lease is lost.
    pub fn assert_active(&self) -> Result<(), IncusError> {
        if self.is_aborted() {
            return Err(self.abort_error());
        }
        Ok(())
    }

    /// The error thrown when the guard has been aborted.
    pub fn abort_error(&self) -> IncusError {
        IncusError::Aborted(
            self.abort_reason()
                .unwrap_or_else(|| DEFAULT_ABORT_REASON.to_string()),
        )
    }
}

tokio::task_local! {
    static GUARD: Option<Arc<IncusExecutionGuard>>;
}

/// Run a future with the given guard installed as the ambient Incus execution
/// guard (TS: runWithIncusExecutionGuard).
pub async fn run_with_incus_execution_guard<F: Future>(
    guard: Arc<IncusExecutionGuard>,
    fut: F,
) -> F::Output {
    GUARD
        .scope(Some(guard), fut)
        .await
}

/// The ambient guard for the current task, if one was installed.
pub fn get_incus_execution_guard() -> Option<Arc<IncusExecutionGuard>> {
    GUARD.try_with(|g| g.clone()).unwrap_or(None)
}

/// Mirrors `throwIfIncusExecutionAborted()` — errors with the abort reason when
/// the ambient guard has been aborted.
pub fn throw_if_incus_execution_aborted() -> Result<(), IncusError> {
    match get_incus_execution_guard() {
        Some(guard) if guard.is_aborted() => Err(guard.abort_error()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_guard_is_scoped_to_the_worker_async_context() {
        let controller = Arc::new(IncusExecutionGuard::new());
        let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let inner_checks = checks.clone();
        let inner_controller = controller.clone();
        run_with_incus_execution_guard(
            controller.clone(),
            async move {
                let ambient = get_incus_execution_guard().expect("guard installed inside scope");
                assert!(Arc::ptr_eq(&ambient, &inner_controller));
                ambient
                    .assert_active()
                    .expect("guard is active before abort");
                inner_checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        )
        .await;

        assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(get_incus_execution_guard().is_none());
    }

    #[tokio::test]
    async fn aborted_execution_guard_fences_later_stages() {
        let controller = Arc::new(IncusExecutionGuard::new());
        let reason = "lease lost";

        let result: Result<(), IncusError> = run_with_incus_execution_guard(
            controller.clone(),
            async move {
                controller.abort(reason);
                throw_if_incus_execution_aborted()
            },
        )
        .await;

        match result {
            Err(IncusError::Aborted(message)) => assert_eq!(message, "lease lost"),
            other => panic!("expected aborted error, got {:?}", other),
        }
    }
}
