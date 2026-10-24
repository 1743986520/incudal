//! Instance swap size resolution.
//! Port of lib/instance-swap.ts.

/// Mirrors `resolveEffectiveSwapSize`.
pub fn resolve_effective_swap_size(instance_size_mb: Option<i64>, plan_size_mb: Option<i64>) -> i64 {
    if let Some(size) = normalize_configured_swap_size(instance_size_mb) {
        return size;
    }
    normalize_configured_swap_size(plan_size_mb).unwrap_or(0)
}

/// Mirrors `shouldSyncInstanceSwapSizeWithPlan`.
pub fn should_sync_instance_swap_size_with_plan(
    instance_size_mb: Option<i64>,
    previous_plan_size_mb: Option<i64>,
) -> bool {
    match normalize_configured_swap_size(instance_size_mb) {
        None => true,
        Some(instance_size) => {
            instance_size == normalize_configured_swap_size(previous_plan_size_mb).unwrap_or(0)
        }
    }
}

/// Mirrors `formatIncusSwapLimit`.
pub fn format_incus_swap_limit(size_mb: i64) -> String {
    format!("{}MiB", size_mb.max(0))
}

/// Mirrors `resolveIncusSwapValue`.
pub fn resolve_incus_swap_value(enabled: bool, size_mb: Option<i64>) -> String {
    match size_mb {
        Some(size) if enabled && size > 0 => format_incus_swap_limit(size),
        _ => "false".to_string(),
    }
}

fn normalize_configured_swap_size(size_mb: Option<i64>) -> Option<i64> {
    size_mb.map(|size| size.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_swap_prefers_instance_value() {
        assert_eq!(resolve_effective_swap_size(Some(512), Some(1024)), 512);
        assert_eq!(resolve_effective_swap_size(None, Some(1024)), 1024);
        assert_eq!(resolve_effective_swap_size(None, None), 0);
        assert_eq!(resolve_effective_swap_size(Some(-5), Some(10)), 0);
    }

    #[test]
    fn sync_check_follows_plan_changes() {
        // Unset instance size always follows the plan.
        assert!(should_sync_instance_swap_size_with_plan(None, Some(512)));
        // Instance size still equal to the previous plan -> keep following it.
        assert!(should_sync_instance_swap_size_with_plan(Some(512), Some(512)));
        // Instance size was customized -> keep the override.
        assert!(!should_sync_instance_swap_size_with_plan(Some(512), Some(1024)));
        // TS: (512, null) compares against the 0 fallback, so no sync.
        assert!(!should_sync_instance_swap_size_with_plan(Some(512), None));
    }

    #[test]
    fn incus_swap_value_matches_ts() {
        assert_eq!(resolve_incus_swap_value(true, Some(512)), "512MiB");
        assert_eq!(resolve_incus_swap_value(false, Some(512)), "false");
        assert_eq!(resolve_incus_swap_value(true, Some(0)), "false");
        assert_eq!(resolve_incus_swap_value(true, None), "false");
    }
}
