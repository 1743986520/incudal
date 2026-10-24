//! Standardized API error codes and messages.
//! Verbatim port of server/src/lib/errors.ts — the frontend matches on `code`,
//! so these strings are a wire contract and must not be reworded.
//!
//! Response shape: `{ "error": <human message>, "code": <machine code>, "details"?: string }`

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

#[allow(non_upper_case_globals)]
pub mod code {
    // Common errors
    pub const INVALID_ID: &str = "INVALID_ID";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const FORBIDDEN: &str = "FORBIDDEN";
    pub const ADMIN_REQUIRED: &str = "ADMIN_REQUIRED";
    pub const FEATURE_DISABLED: &str = "FEATURE_DISABLED";
    pub const TELEGRAM_BINDING_REQUIRED: &str = "TELEGRAM_BINDING_REQUIRED";

    // User errors
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const USER_EXISTS: &str = "USER_EXISTS";
    pub const CANNOT_MODIFY_SELF: &str = "CANNOT_MODIFY_SELF";
    pub const CANNOT_DELETE_SELF: &str = "CANNOT_DELETE_SELF";
    pub const CANNOT_BAN_ADMIN: &str = "CANNOT_BAN_ADMIN";
    pub const CANNOT_DELETE_ADMIN: &str = "CANNOT_DELETE_ADMIN";
    pub const USER_HAS_INSTANCES: &str = "USER_HAS_INSTANCES";

    // Auth errors
    pub const INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";
    pub const ACCOUNT_BANNED: &str = "ACCOUNT_BANNED";
    pub const TOO_MANY_ATTEMPTS: &str = "TOO_MANY_ATTEMPTS";
    pub const REGISTRATION_DISABLED: &str = "REGISTRATION_DISABLED";
    pub const INVALID_INVITE_CODE: &str = "INVALID_INVITE_CODE";
    pub const INVITE_CODE_EXPIRED: &str = "INVITE_CODE_EXPIRED";
    pub const INVALID_2FA_CODE: &str = "INVALID_2FA_CODE";
    pub const TWO_FA_REQUIRED: &str = "TWO_FA_REQUIRED";
    pub const TWO_FA_ALREADY_ENABLED: &str = "TWO_FA_ALREADY_ENABLED";
    pub const TWO_FA_NOT_ENABLED: &str = "TWO_FA_NOT_ENABLED";
    pub const REFRESH_TOKEN_MISSING: &str = "REFRESH_TOKEN_MISSING";
    pub const REFRESH_TOKEN_INVALID: &str = "REFRESH_TOKEN_INVALID";
    pub const SESSION_NOT_FOUND: &str = "SESSION_NOT_FOUND";

    // Validation errors
    pub const INVALID_EMAIL: &str = "INVALID_EMAIL";
    pub const EMAIL_CONTAINS_ILLEGAL: &str = "EMAIL_CONTAINS_ILLEGAL";
    pub const USERNAME_CONTAINS_ILLEGAL: &str = "USERNAME_CONTAINS_ILLEGAL";
    pub const PASSWORD_TOO_WEAK: &str = "PASSWORD_TOO_WEAK";
    pub const INVALID_SSH_KEY: &str = "INVALID_SSH_KEY";
    pub const SSH_KEY_EXISTS: &str = "SSH_KEY_EXISTS";
    pub const INVALID_NAME: &str = "INVALID_NAME";

    // Instance errors
    pub const INSTANCE_NOT_FOUND: &str = "INSTANCE_NOT_FOUND";
    pub const INSTANCE_ALREADY_RUNNING: &str = "INSTANCE_ALREADY_RUNNING";
    pub const INSTANCE_ALREADY_STOPPED: &str = "INSTANCE_ALREADY_STOPPED";
    pub const INSTANCE_STATUS_INVALID: &str = "INSTANCE_STATUS_INVALID";
    pub const INSTANCE_SUSPENDED: &str = "INSTANCE_SUSPENDED";
    pub const INSTANCE_NOT_SUSPENDED: &str = "INSTANCE_NOT_SUSPENDED";
    pub const INSTANCE_SUSPENDED_EXPIRED: &str = "INSTANCE_SUSPENDED_EXPIRED";
    pub const INSTANCE_DESTROY_TRAFFIC_LIMIT_EXCEEDED: &str =
        "INSTANCE_DESTROY_TRAFFIC_LIMIT_EXCEEDED";
    pub const INSTANCE_DELETION_NOT_ALLOWED: &str = "INSTANCE_DELETION_NOT_ALLOWED";

    // Host errors
    pub const HOST_NOT_FOUND: &str = "HOST_NOT_FOUND";
    pub const HOST_OFFLINE: &str = "HOST_OFFLINE";
    pub const HOST_ONLINE: &str = "HOST_ONLINE";
    pub const HOST_HAS_INSTANCES: &str = "HOST_HAS_INSTANCES";
    pub const HOST_ALREADY_OFFICIAL: &str = "HOST_ALREADY_OFFICIAL";
    pub const HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT: &str =
        "HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT";
    pub const NO_AVAILABLE_HOSTS: &str = "NO_AVAILABLE_HOSTS";

    // Image errors
    pub const IMAGE_NOT_FOUND: &str = "IMAGE_NOT_FOUND";
    pub const IMAGE_SYNCED_ON_HOSTS: &str = "IMAGE_SYNCED_ON_HOSTS";
    pub const IMAGE_TYPE_MISMATCH: &str = "IMAGE_TYPE_MISMATCH";
    pub const IMAGE_MEMORY_INCOMPATIBLE: &str = "IMAGE_MEMORY_INCOMPATIBLE";

    // Package errors
    pub const PACKAGE_NOT_FOUND: &str = "PACKAGE_NOT_FOUND";
    pub const PACKAGE_IN_USE: &str = "PACKAGE_IN_USE";
    pub const PACKAGE_PREREQUISITE_MISSING: &str = "PACKAGE_PREREQUISITE_MISSING";

    // Quota errors
    pub const QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";
    pub const QUOTA_CPU_EXCEEDED: &str = "QUOTA_CPU_EXCEEDED";
    pub const QUOTA_MEMORY_EXCEEDED: &str = "QUOTA_MEMORY_EXCEEDED";
    pub const QUOTA_DISK_EXCEEDED: &str = "QUOTA_DISK_EXCEEDED";
    pub const QUOTA_INSTANCE_EXCEEDED: &str = "QUOTA_INSTANCE_EXCEEDED";
    pub const QUOTA_PORT_EXCEEDED: &str = "QUOTA_PORT_EXCEEDED";
    pub const QUOTA_SNAPSHOT_EXCEEDED: &str = "QUOTA_SNAPSHOT_EXCEEDED";
    pub const QUOTA_BACKUP_EXCEEDED: &str = "QUOTA_BACKUP_EXCEEDED";
    pub const QUOTA_NOT_ALLOCATED: &str = "QUOTA_NOT_ALLOCATED";

    // Snapshot errors
    pub const SNAPSHOT_NOT_FOUND: &str = "SNAPSHOT_NOT_FOUND";
    pub const SNAPSHOT_RESTORE_REQUIRES_STOP: &str = "SNAPSHOT_RESTORE_REQUIRES_STOP";

    // Backup errors
    pub const BACKUP_NOT_FOUND: &str = "BACKUP_NOT_FOUND";
    pub const BACKUP_NOT_READY: &str = "BACKUP_NOT_READY";
    pub const EXPORT_TASK_NOT_FOUND: &str = "EXPORT_TASK_NOT_FOUND";
    pub const EXPORT_TASK_EXPIRED: &str = "EXPORT_TASK_EXPIRED";

    // Port mapping errors
    pub const PORT_IN_USE: &str = "PORT_IN_USE";
    pub const PORT_OUT_OF_RANGE: &str = "PORT_OUT_OF_RANGE";
    pub const PORT_MAPPING_NOT_FOUND: &str = "PORT_MAPPING_NOT_FOUND";
    pub const PORT_CONFLICT: &str = "PORT_CONFLICT";
    pub const PORT_RANGE_MISMATCH: &str = "PORT_RANGE_MISMATCH";
    pub const QUOTA_PORT_BATCH_EXCEEDED: &str = "QUOTA_PORT_BATCH_EXCEEDED";

    // Notification errors
    pub const NOTIFICATION_CHANNEL_NOT_FOUND: &str = "NOTIFICATION_CHANNEL_NOT_FOUND";

    // Help errors
    pub const ARTICLE_NOT_FOUND: &str = "ARTICLE_NOT_FOUND";
    pub const SLUG_EXISTS: &str = "SLUG_EXISTS";

    // Invite code errors
    pub const INVITE_CODE_USED: &str = "INVITE_CODE_USED";
    pub const INVITE_CODE_NOT_FOUND: &str = "INVITE_CODE_NOT_FOUND";

    // OAuth errors
    pub const OAUTH_PROVIDER_DISABLED: &str = "OAUTH_PROVIDER_DISABLED";
    pub const OAUTH_ALREADY_BOUND: &str = "OAUTH_ALREADY_BOUND";
    pub const OAUTH_NOT_BOUND: &str = "OAUTH_NOT_BOUND";
    pub const OAUTH_TOKEN_ERROR: &str = "OAUTH_TOKEN_ERROR";

    // SSH Key errors
    pub const SSH_KEY_NOT_FOUND: &str = "SSH_KEY_NOT_FOUND";
    pub const SSH_KEY_REQUIRED: &str = "SSH_KEY_REQUIRED";
    pub const SSH_KEY_NOT_OWNED: &str = "SSH_KEY_NOT_OWNED";

    // Package/Plan errors
    pub const PACKAGE_UNAVAILABLE: &str = "PACKAGE_UNAVAILABLE";
    pub const PLAN_REQUIRED: &str = "PLAN_REQUIRED";
    pub const PLAN_NOT_FOUND: &str = "PLAN_NOT_FOUND";
    pub const PLAN_INACTIVE: &str = "PLAN_INACTIVE";
    pub const PLAN_SOLD_OUT: &str = "PLAN_SOLD_OUT";
    pub const CANNOT_CREATE_OWN_PAID_PACKAGE: &str = "CANNOT_CREATE_OWN_PAID_PACKAGE";
    pub const BALANCE_INSUFFICIENT: &str = "BALANCE_INSUFFICIENT";
    pub const TRAFFIC_RESET_NOT_ALLOWED: &str = "TRAFFIC_RESET_NOT_ALLOWED";
    pub const TRAFFIC_RESET_NOT_NEEDED: &str = "TRAFFIC_RESET_NOT_NEEDED";
    pub const BALANCE_TRANSFER_DISABLED: &str = "BALANCE_TRANSFER_DISABLED";
    pub const BALANCE_TRANSFER_TO_SELF: &str = "BALANCE_TRANSFER_TO_SELF";
    pub const BALANCE_TRANSFER_RECIPIENT_BANNED: &str = "BALANCE_TRANSFER_RECIPIENT_BANNED";
    pub const BALANCE_TRANSFER_AMOUNT_INVALID: &str = "BALANCE_TRANSFER_AMOUNT_INVALID";
    pub const BALANCE_TRANSFER_INSUFFICIENT_BALANCE: &str =
        "BALANCE_TRANSFER_INSUFFICIENT_BALANCE";
    pub const BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED: &str =
        "BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED";

    // Host resource errors
    pub const HOST_UNAVAILABLE: &str = "HOST_UNAVAILABLE";
    pub const HOST_NO_ONLINE: &str = "HOST_NO_ONLINE";
    pub const HOST_RESOURCES_NOT_SYNCED: &str = "HOST_RESOURCES_NOT_SYNCED";
    pub const HOST_NODE_GROUP_NO_HOSTS: &str = "HOST_NODE_GROUP_NO_HOSTS";
    pub const HOST_RESOURCES_INSUFFICIENT: &str = "HOST_RESOURCES_INSUFFICIENT";
    pub const HOST_NAME_EXISTS: &str = "HOST_NAME_EXISTS";
    pub const HOST_ADDRESS_EXISTS: &str = "HOST_ADDRESS_EXISTS";
    pub const HOST_ADDRESS_UNRESOLVABLE: &str = "HOST_ADDRESS_UNRESOLVABLE";
    pub const HOST_CERT_NOT_CONFIGURED: &str = "HOST_CERT_NOT_CONFIGURED";
    pub const HOST_INVALID_CPU_MAX: &str = "HOST_INVALID_CPU_MAX";
    pub const HOST_INVALID_MEMORY_MAX: &str = "HOST_INVALID_MEMORY_MAX";
    pub const HOST_INVALID_IPV6_MODE: &str = "HOST_INVALID_IPV6_MODE";
    pub const HOST_IPV6_ROUTE_REQUIRES_CONFIG: &str = "HOST_IPV6_ROUTE_REQUIRES_CONFIG";
    pub const HOST_CPU_BELOW_USED: &str = "HOST_CPU_BELOW_USED";
    pub const HOST_MEMORY_BELOW_USED: &str = "HOST_MEMORY_BELOW_USED";
    pub const HOST_INSTANCE_TYPE_MISMATCH: &str = "HOST_INSTANCE_TYPE_MISMATCH";

    // Instance operation errors
    pub const INSTANCE_STOP_REQUIRED: &str = "INSTANCE_STOP_REQUIRED";
    pub const INSTANCE_IMAGE_REQUIRED: &str = "INSTANCE_IMAGE_REQUIRED";
    pub const INSTANCE_IMAGE_UNAVAILABLE: &str = "INSTANCE_IMAGE_UNAVAILABLE";
    pub const INSTANCE_REBUILD_FAILED: &str = "INSTANCE_REBUILD_FAILED";
    pub const INSTANCE_CLONE_FAILED: &str = "INSTANCE_CLONE_FAILED";
    pub const INSTANCE_IPV6_NOT_SUPPORTED: &str = "INSTANCE_IPV6_NOT_SUPPORTED";
    pub const INSTANCE_IPV6_REASSIGN_FAILED: &str = "INSTANCE_IPV6_REASSIGN_FAILED";
    pub const INSTANCE_NO_IPV4: &str = "INSTANCE_NO_IPV4";
    pub const HOST_NO_IPV6_SUBNET: &str = "HOST_NO_IPV6_SUBNET";
    pub const IPV6_POOL_EXHAUSTED: &str = "IPV6_POOL_EXHAUSTED";
    pub const IPV6_REASSIGN_COOLDOWN: &str = "IPV6_REASSIGN_COOLDOWN";

    // Port mapping errors (additional)
    pub const PORT_MAPPING_NAT_ONLY: &str = "PORT_MAPPING_NAT_ONLY";
    pub const PORT_NO_AVAILABLE: &str = "PORT_NO_AVAILABLE";
    pub const PORT_MAPPING_INVALID_ID: &str = "PORT_MAPPING_INVALID_ID";

    // Image errors (additional)
    pub const IMAGE_CREATE_FAILED: &str = "IMAGE_CREATE_FAILED";
    pub const IMAGE_UPDATE_FAILED: &str = "IMAGE_UPDATE_FAILED";
    pub const IMAGE_INVALID_HOST_ID: &str = "IMAGE_INVALID_HOST_ID";

    // Backup errors (additional)
    pub const BACKUP_CREATE_FAILED: &str = "BACKUP_CREATE_FAILED";
    pub const BACKUP_DELETE_FAILED: &str = "BACKUP_DELETE_FAILED";
    pub const BACKUP_EXPORT_FAILED: &str = "BACKUP_EXPORT_FAILED";
    pub const BACKUP_QUOTA_NOT_SET: &str = "BACKUP_QUOTA_NOT_SET";
    pub const BACKUP_EXPORT_STATUS_INVALID: &str = "BACKUP_EXPORT_STATUS_INVALID";

    // Config errors
    pub const CONFIG_INVALID_KEY: &str = "CONFIG_INVALID_KEY";
    pub const CONFIG_INVALID_VALUE: &str = "CONFIG_INVALID_VALUE";

    // Snapshot errors (additional)
    pub const SNAPSHOT_QUOTA_NOT_SET: &str = "SNAPSHOT_QUOTA_NOT_SET";

    // Package errors (additional)
    pub const PACKAGE_HAS_INSTANCES: &str = "PACKAGE_HAS_INSTANCES";

    // Resource limit errors
    pub const RESOURCE_CPU_EXCEEDS_PACKAGE: &str = "RESOURCE_CPU_EXCEEDS_PACKAGE";
    pub const RESOURCE_MEMORY_EXCEEDS_PACKAGE: &str = "RESOURCE_MEMORY_EXCEEDS_PACKAGE";
    pub const RESOURCE_DISK_EXCEEDS_PACKAGE: &str = "RESOURCE_DISK_EXCEEDS_PACKAGE";

    // User quota errors (detailed)
    pub const QUOTA_CPU_INSUFFICIENT: &str = "QUOTA_CPU_INSUFFICIENT";
    pub const QUOTA_MEMORY_INSUFFICIENT: &str = "QUOTA_MEMORY_INSUFFICIENT";
    pub const QUOTA_DISK_INSUFFICIENT: &str = "QUOTA_DISK_INSUFFICIENT";
    pub const QUOTA_INSTANCE_LIMIT_REACHED: &str = "QUOTA_INSTANCE_LIMIT_REACHED";
    pub const QUOTA_HOST_LIMIT_REACHED: &str = "QUOTA_HOST_LIMIT_REACHED";
    pub const QUOTA_PACKAGE_LIMIT_REACHED: &str = "QUOTA_PACKAGE_LIMIT_REACHED";
    pub const QUOTA_FRIEND_LIMIT_REACHED: &str = "QUOTA_FRIEND_LIMIT_REACHED";
    pub const QUOTA_PORT_BELOW_USED: &str = "QUOTA_PORT_BELOW_USED";
    pub const QUOTA_SNAPSHOT_BELOW_USED: &str = "QUOTA_SNAPSHOT_BELOW_USED";
    pub const QUOTA_BACKUP_BELOW_USED: &str = "QUOTA_BACKUP_BELOW_USED";
    pub const QUOTA_PORT_TOTAL_EXCEEDED: &str = "QUOTA_PORT_TOTAL_EXCEEDED";
    pub const QUOTA_SNAPSHOT_TOTAL_EXCEEDED: &str = "QUOTA_SNAPSHOT_TOTAL_EXCEEDED";
    pub const QUOTA_BACKUP_TOTAL_EXCEEDED: &str = "QUOTA_BACKUP_TOTAL_EXCEEDED";

    // Image errors (additional)
    pub const IMAGE_NOT_SYNCED: &str = "IMAGE_NOT_SYNCED";
    pub const IMAGE_SYNCING_CANNOT_DELETE: &str = "IMAGE_SYNCING_CANNOT_DELETE";
    pub const IMAGE_NO_HOSTS: &str = "IMAGE_NO_HOSTS";

    // Port errors (additional)
    pub const PORT_RANGE_INVALID: &str = "PORT_RANGE_INVALID";

    // Snapshot policy errors
    pub const SNAPSHOT_MANUAL_FULL: &str = "SNAPSHOT_MANUAL_FULL";
    pub const SNAPSHOT_RETENTION_EXCEEDS: &str = "SNAPSHOT_RETENTION_EXCEEDS";

    // Backup policy errors
    pub const BACKUP_MANUAL_FULL: &str = "BACKUP_MANUAL_FULL";
    pub const BACKUP_RETENTION_EXCEEDS: &str = "BACKUP_RETENTION_EXCEEDS";

    // OAuth errors (additional)
    pub const OAUTH_NOT_ENABLED: &str = "OAUTH_NOT_ENABLED";

    // Storage config errors
    pub const STORAGE_CONFIG_NOT_FOUND: &str = "STORAGE_CONFIG_NOT_FOUND";
    pub const STORAGE_CONFIG_CREATE_FAILED: &str = "STORAGE_CONFIG_CREATE_FAILED";
    pub const STORAGE_CONFIG_UPDATE_FAILED: &str = "STORAGE_CONFIG_UPDATE_FAILED";
    pub const STORAGE_CONFIG_DELETE_FAILED: &str = "STORAGE_CONFIG_DELETE_FAILED";
    pub const STORAGE_TYPE_NOT_SUPPORTED: &str = "STORAGE_TYPE_NOT_SUPPORTED";
    pub const STORAGE_POOL_NOT_CONFIGURED: &str = "STORAGE_POOL_NOT_CONFIGURED";

    // Backup upload errors
    pub const BACKUP_UPLOAD_TASK_NOT_FOUND: &str = "BACKUP_UPLOAD_TASK_NOT_FOUND";
    pub const BACKUP_UPLOAD_IN_PROGRESS: &str = "BACKUP_UPLOAD_IN_PROGRESS";
    pub const BACKUP_UPLOAD_FAILED: &str = "BACKUP_UPLOAD_FAILED";

    // Instance config errors
    pub const CONFIG_DISK_CANNOT_SHRINK: &str = "CONFIG_DISK_CANNOT_SHRINK";
    pub const CONFIG_NO_CHANGES: &str = "CONFIG_NO_CHANGES";
    pub const CONFIG_UPDATE_FAILED: &str = "CONFIG_UPDATE_FAILED";

    // Transfer errors
    pub const TRANSFER_NOT_FOUND: &str = "TRANSFER_NOT_FOUND";
    pub const TRANSFER_TO_SELF: &str = "TRANSFER_TO_SELF";
    pub const TRANSFER_TO_BANNED: &str = "TRANSFER_TO_BANNED";
    pub const TRANSFER_ALREADY_PENDING: &str = "TRANSFER_ALREADY_PENDING";
    pub const TRANSFER_NOT_PENDING: &str = "TRANSFER_NOT_PENDING";
    pub const TRANSFER_INVALID_STATUS: &str = "TRANSFER_INVALID_STATUS";
    pub const TRANSFER_QUOTA_NOT_FOUND: &str = "TRANSFER_QUOTA_NOT_FOUND";
    pub const TRANSFER_QUOTA_INSUFFICIENT: &str = "TRANSFER_QUOTA_INSUFFICIENT";
    pub const TRANSFER_INSTANCE_LOCKED: &str = "TRANSFER_INSTANCE_LOCKED";
    pub const TRANSFER_INSUFFICIENT_BALANCE: &str = "TRANSFER_INSUFFICIENT_BALANCE";
    pub const TRANSFER_HOST_DISABLED: &str = "TRANSFER_HOST_DISABLED";
    pub const INVALID_PARAMS: &str = "INVALID_PARAMS";

    // Friend system errors
    pub const CANNOT_ADD_SELF: &str = "CANNOT_ADD_SELF";
    pub const ALREADY_FRIENDS: &str = "ALREADY_FRIENDS";
    pub const FRIEND_REQUEST_PENDING: &str = "FRIEND_REQUEST_PENDING";
    pub const FRIEND_REQUEST_NOT_FOUND: &str = "FRIEND_REQUEST_NOT_FOUND";
    pub const FRIEND_REQUEST_NOT_PENDING: &str = "FRIEND_REQUEST_NOT_PENDING";
    pub const FRIENDSHIP_NOT_FOUND: &str = "FRIENDSHIP_NOT_FOUND";
    pub const NOT_FRIENDS: &str = "NOT_FRIENDS";
    pub const TARGET_FRIEND_QUOTA_FULL: &str = "TARGET_FRIEND_QUOTA_FULL";

    // Package share errors
    pub const CANNOT_SHARE_TO_SELF: &str = "CANNOT_SHARE_TO_SELF";
    pub const PACKAGE_ALREADY_SHARED: &str = "PACKAGE_ALREADY_SHARED";
    pub const SHARE_NOT_FOUND: &str = "SHARE_NOT_FOUND";
    pub const SHARE_QUOTA_CPU_EXCEEDED: &str = "SHARE_QUOTA_CPU_EXCEEDED";
    pub const SHARE_QUOTA_MEMORY_EXCEEDED: &str = "SHARE_QUOTA_MEMORY_EXCEEDED";
    pub const SHARE_QUOTA_INSTANCES_EXCEEDED: &str = "SHARE_QUOTA_INSTANCES_EXCEEDED";

    // Email verification errors
    pub const EMAIL_VERIFICATION_DISABLED: &str = "EMAIL_VERIFICATION_DISABLED";
    pub const EMAIL_CODE_REQUIRED: &str = "EMAIL_CODE_REQUIRED";
    pub const INVALID_EMAIL_CODE: &str = "INVALID_EMAIL_CODE";
    pub const TOO_MANY_VERIFICATION_REQUESTS: &str = "TOO_MANY_VERIFICATION_REQUESTS";
    pub const EMAIL_SEND_FAILED: &str = "EMAIL_SEND_FAILED";
    pub const EMAIL_ALREADY_REGISTERED: &str = "EMAIL_ALREADY_REGISTERED";
    pub const EMAIL_DOMAIN_NOT_ALLOWED: &str = "EMAIL_DOMAIN_NOT_ALLOWED";

    // Inbox errors
    pub const MESSAGE_NOT_FOUND: &str = "MESSAGE_NOT_FOUND";

    // Checkin errors
    pub const CHECKIN_NO_INSTANCE: &str = "CHECKIN_NO_INSTANCE";
    pub const CHECKIN_ALREADY_TODAY: &str = "CHECKIN_ALREADY_TODAY";
    pub const REDEEM_ALREADY_TODAY: &str = "REDEEM_ALREADY_TODAY";
    pub const REDEEM_CODE_NOT_FOUND: &str = "REDEEM_CODE_NOT_FOUND";
    pub const REDEEM_CODE_USED: &str = "REDEEM_CODE_USED";
    pub const REDEEM_CODE_EXPIRED: &str = "REDEEM_CODE_EXPIRED";
    pub const REDEEM_CODE_SELF_ONLY: &str = "REDEEM_CODE_SELF_ONLY";
    pub const REDEEM_CODE_DISABLED: &str = "REDEEM_CODE_DISABLED";
    pub const REDEEM_CODE_INVALID_FORMAT: &str = "REDEEM_CODE_INVALID_FORMAT";
    pub const REDEEM_CODE_EXHAUSTED: &str = "REDEEM_CODE_EXHAUSTED";
    pub const REDEEM_CODE_ALREADY_USED_BY_USER: &str = "REDEEM_CODE_ALREADY_USED_BY_USER";
    pub const REDEEM_CODE_HOST_MISMATCH: &str = "REDEEM_CODE_HOST_MISMATCH";
    pub const REDEEM_CODE_BATCH_LIMIT: &str = "REDEEM_CODE_BATCH_LIMIT";
    pub const REDEEM_EXCEEDS_PACKAGE_QUOTA: &str = "REDEEM_EXCEEDS_PACKAGE_QUOTA";
    pub const REDEEM_ALREADY_AT_LIMIT: &str = "REDEEM_ALREADY_AT_LIMIT";
    pub const CHECKIN_CODE_PAID_INSTANCE: &str = "CHECKIN_CODE_PAID_INSTANCE";

    // Official coupon errors
    pub const COUPON_NOT_FOUND: &str = "COUPON_NOT_FOUND";
    pub const COUPON_DISABLED: &str = "COUPON_DISABLED";
    pub const COUPON_NOT_STARTED: &str = "COUPON_NOT_STARTED";
    pub const COUPON_EXPIRED: &str = "COUPON_EXPIRED";
    pub const COUPON_SCOPE_MISMATCH: &str = "COUPON_SCOPE_MISMATCH";
    pub const COUPON_USER_LIMIT_REACHED: &str = "COUPON_USER_LIMIT_REACHED";
    pub const COUPON_EXHAUSTED: &str = "COUPON_EXHAUSTED";
    pub const COUPON_CODE_EXISTS: &str = "COUPON_CODE_EXISTS";
    pub const COUPON_IN_USE: &str = "COUPON_IN_USE";
    pub const COUPON_INVALID_DISCOUNT: &str = "COUPON_INVALID_DISCOUNT";

    // Resource Pool errors
    pub const RESOURCE_POOL_INSUFFICIENT: &str = "RESOURCE_POOL_INSUFFICIENT";
    pub const RESOURCE_POOL_KVM_CPU_MULTIPLE: &str = "RESOURCE_POOL_KVM_CPU_MULTIPLE";
    pub const RESOURCE_POOL_KVM_MEMORY_MULTIPLE: &str = "RESOURCE_POOL_KVM_MEMORY_MULTIPLE";
    pub const RESOURCE_POOL_KVM_DISK_MULTIPLE: &str = "RESOURCE_POOL_KVM_DISK_MULTIPLE";
    pub const RESOURCE_POOL_VM_MUST_STOP: &str = "RESOURCE_POOL_VM_MUST_STOP";
    pub const RESOURCE_POOL_SYSTEM_CODE_REQUIRES_INSTANCE: &str =
        "RESOURCE_POOL_SYSTEM_CODE_REQUIRES_INSTANCE";

    // Internal errors
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";

    // Mail module errors
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
    pub const OPERATION_NOT_ALLOWED: &str = "OPERATION_NOT_ALLOWED";
    pub const RESOURCE_EXISTS: &str = "RESOURCE_EXISTS";
    pub const UPSTREAM_ERROR: &str = "UPSTREAM_ERROR";
    pub const INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";

    // Ad hoc codes (defined outside lib/errors.ts in the TS server)
    pub const AGENT_AUTH_REQUIRED: &str = "AGENT_AUTH_REQUIRED";
    pub const AGENT_AUTH_INVALID: &str = "AGENT_AUTH_INVALID";
    pub const AGENT_AUTH_EXPIRED: &str = "AGENT_AUTH_EXPIRED";
    pub const AGENT_BODY_HASH_MISMATCH: &str = "AGENT_BODY_HASH_MISMATCH";
    pub const AGENT_DISABLED: &str = "AGENT_DISABLED";
    pub const AGENT_SECRET_INVALID: &str = "AGENT_SECRET_INVALID";
    pub const AGENT_SIGNATURE_INVALID: &str = "AGENT_SIGNATURE_INVALID";
    pub const AGENT_NONCE_REPLAY: &str = "AGENT_NONCE_REPLAY";
    pub const RESOURCE_BUSY: &str = "RESOURCE_BUSY";
    pub const LOGOUT_FAILED: &str = "LOGOUT_FAILED";
    pub const TURNSTILE_NOT_CONFIGURED: &str = "TURNSTILE_NOT_CONFIGURED";
    pub const TURNSTILE_TOKEN_MISSING: &str = "TURNSTILE_TOKEN_MISSING";
    pub const FILE_TOO_LARGE: &str = "FILE_TOO_LARGE";
    pub const IP_LIMIT_EXCEEDED: &str = "IP_LIMIT_EXCEEDED";
    pub const USER_ONLY: &str = "USER_ONLY";
    pub const SESSION_INVALIDATED: &str = "SESSION_INVALIDATED";
    pub const NOT_PORTED: &str = "NOT_PORTED";
}

/// English error messages (default). Linear lookup is fine: only error paths hit it.
pub fn message(code: &str) -> Option<&'static str> {
    MESSAGES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, m)| *m)
}

static MESSAGES: &[(&str, &str)] = &[
    ("INVALID_ID", "Invalid ID"),
    ("NOT_FOUND", "Resource not found"),
    ("UNAUTHORIZED", "Unauthorized"),
    ("FORBIDDEN", "Access denied"),
    ("ADMIN_REQUIRED", "Admin privileges required"),
    ("FEATURE_DISABLED", "This feature has been disabled"),
    (
        "TELEGRAM_BINDING_REQUIRED",
        "Bind a Telegram account before using the panel",
    ),
    ("USER_NOT_FOUND", "User not found"),
    ("USER_EXISTS", "Username already exists"),
    ("CANNOT_MODIFY_SELF", "Cannot modify your own status"),
    ("CANNOT_DELETE_SELF", "Cannot delete yourself"),
    ("CANNOT_BAN_ADMIN", "Cannot ban admin account"),
    ("CANNOT_DELETE_ADMIN", "Cannot delete admin account"),
    (
        "USER_HAS_INSTANCES",
        "User has instances, please delete them first",
    ),
    ("INVALID_CREDENTIALS", "Invalid username or password"),
    ("ACCOUNT_BANNED", "Account has been disabled"),
    (
        "TOO_MANY_ATTEMPTS",
        "Too many login attempts, please try again later",
    ),
    ("REGISTRATION_DISABLED", "Registration is currently closed"),
    ("INVALID_INVITE_CODE", "Invalid or used invite code"),
    ("INVITE_CODE_EXPIRED", "Invite code has expired"),
    (
        "INVALID_2FA_CODE",
        "Invalid verification code or recovery code",
    ),
    ("TWO_FA_REQUIRED", "Two-factor authentication required"),
    (
        "TWO_FA_ALREADY_ENABLED",
        "2FA is already enabled, please disable it first",
    ),
    ("TWO_FA_NOT_ENABLED", "2FA is not enabled"),
    ("REFRESH_TOKEN_MISSING", "Refresh token missing"),
    ("REFRESH_TOKEN_INVALID", "Refresh token invalid or expired"),
    ("SESSION_NOT_FOUND", "Session not found"),
    ("INVALID_EMAIL", "Please enter a valid email address"),
    ("EMAIL_CONTAINS_ILLEGAL", "Email contains illegal characters"),
    (
        "USERNAME_CONTAINS_ILLEGAL",
        "Username contains illegal characters",
    ),
    ("PASSWORD_TOO_WEAK", "Password is too weak"),
    ("INVALID_SSH_KEY", "Invalid SSH public key format"),
    ("SSH_KEY_EXISTS", "This SSH key has already been added"),
    ("INVALID_NAME", "Invalid name format"),
    ("INSTANCE_NOT_FOUND", "Instance not found"),
    ("INSTANCE_ALREADY_RUNNING", "Instance is already running"),
    ("INSTANCE_ALREADY_STOPPED", "Instance is already stopped"),
    (
        "INSTANCE_STATUS_INVALID",
        "Instance status does not allow this operation",
    ),
    (
        "INSTANCE_SUSPENDED",
        "Instance is suspended and cannot be started",
    ),
    ("INSTANCE_NOT_SUSPENDED", "Instance is not in suspended status"),
    (
        "INSTANCE_SUSPENDED_EXPIRED",
        "Instance is suspended due to expiration, please renew to unsuspend",
    ),
    (
        "INSTANCE_DESTROY_TRAFFIC_LIMIT_EXCEEDED",
        "Current monthly traffic cycle usage has reached the destroy limit",
    ),
    (
        "INSTANCE_DELETION_NOT_ALLOWED",
        "This package does not allow user-initiated instance deletion",
    ),
    ("HOST_NOT_FOUND", "Host not found"),
    ("HOST_OFFLINE", "Host is offline"),
    ("HOST_ONLINE", "Host is online, reinstall not needed"),
    (
        "HOST_HAS_INSTANCES",
        "Host has instances, please delete them first",
    ),
    ("HOST_ALREADY_OFFICIAL", "Host is already official"),
    (
        "HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT",
        "Takeover blocked because some packages would lose all bound hosts",
    ),
    ("NO_AVAILABLE_HOSTS", "No available hosts"),
    ("IMAGE_NOT_FOUND", "Image not found"),
    (
        "IMAGE_SYNCED_ON_HOSTS",
        "Image is synced on hosts, please delete from hosts first",
    ),
    (
        "IMAGE_TYPE_MISMATCH",
        "Selected image is not compatible with the package instance type",
    ),
    (
        "IMAGE_MEMORY_INCOMPATIBLE",
        "128MB memory only supports Alpine/Debian images",
    ),
    ("PACKAGE_NOT_FOUND", "Package not found"),
    ("PACKAGE_IN_USE", "Package is in use by instances"),
    (
        "PACKAGE_PREREQUISITE_MISSING",
        "Required package instance is missing",
    ),
    ("QUOTA_EXCEEDED", "Quota exceeded"),
    ("QUOTA_CPU_EXCEEDED", "CPU quota exceeded"),
    ("QUOTA_MEMORY_EXCEEDED", "Memory quota exceeded"),
    ("QUOTA_DISK_EXCEEDED", "Disk quota exceeded"),
    ("QUOTA_INSTANCE_EXCEEDED", "Instance quota exceeded"),
    ("QUOTA_PORT_EXCEEDED", "Port quota exceeded"),
    ("QUOTA_SNAPSHOT_EXCEEDED", "Snapshot quota exceeded"),
    ("QUOTA_BACKUP_EXCEEDED", "Backup quota exceeded"),
    ("QUOTA_NOT_ALLOCATED", "Quota not allocated"),
    ("SNAPSHOT_NOT_FOUND", "Snapshot not found"),
    (
        "SNAPSHOT_RESTORE_REQUIRES_STOP",
        "Please stop the instance before restoring snapshot",
    ),
    ("BACKUP_NOT_FOUND", "Backup not found"),
    ("BACKUP_NOT_READY", "Backup is not ready for export"),
    ("EXPORT_TASK_NOT_FOUND", "Export task not found or expired"),
    ("EXPORT_TASK_EXPIRED", "Export task has expired"),
    ("PORT_IN_USE", "Port is already in use"),
    ("PORT_OUT_OF_RANGE", "Port is out of allowed range"),
    ("PORT_MAPPING_NOT_FOUND", "Port mapping not found"),
    ("PORT_CONFLICT", "Some ports are already in use"),
    (
        "PORT_RANGE_MISMATCH",
        "Private and public port range count must match",
    ),
    (
        "QUOTA_PORT_BATCH_EXCEEDED",
        "Port quota exceeded for batch mapping",
    ),
    (
        "NOTIFICATION_CHANNEL_NOT_FOUND",
        "Notification channel not found",
    ),
    ("ARTICLE_NOT_FOUND", "Article not found"),
    ("SLUG_EXISTS", "Slug already exists"),
    ("INVITE_CODE_USED", "Invite code has been used"),
    ("INVITE_CODE_NOT_FOUND", "Invite code not found"),
    ("OAUTH_PROVIDER_DISABLED", "This login method has been disabled"),
    (
        "OAUTH_ALREADY_BOUND",
        "This account is already bound to another user",
    ),
    ("OAUTH_NOT_BOUND", "Account not bound"),
    ("OAUTH_TOKEN_ERROR", "Failed to get authorization"),
    ("SSH_KEY_NOT_FOUND", "SSH key not found"),
    (
        "SSH_KEY_REQUIRED",
        "SSH key is required, please add one in settings first",
    ),
    (
        "SSH_KEY_NOT_OWNED",
        "SSH key not found or does not belong to this user",
    ),
    ("PACKAGE_UNAVAILABLE", "Package is unavailable or discontinued"),
    (
        "PLAN_REQUIRED",
        "This is a paid package, a plan must be selected",
    ),
    (
        "PLAN_NOT_FOUND",
        "Plan not found or does not belong to this package",
    ),
    ("PLAN_INACTIVE", "Plan is inactive"),
    ("PLAN_SOLD_OUT", "Plan is sold out"),
    (
        "CANNOT_CREATE_OWN_PAID_PACKAGE",
        "Cannot create instance with your own paid package",
    ),
    ("BALANCE_INSUFFICIENT", "Insufficient balance"),
    (
        "TRAFFIC_RESET_NOT_ALLOWED",
        "Traffic reset is not allowed for this instance",
    ),
    ("TRAFFIC_RESET_NOT_NEEDED", "No traffic usage to reset"),
    ("BALANCE_TRANSFER_DISABLED", "Balance transfer is disabled"),
    ("BALANCE_TRANSFER_TO_SELF", "Cannot transfer balance to yourself"),
    (
        "BALANCE_TRANSFER_RECIPIENT_BANNED",
        "Cannot transfer balance to a banned user",
    ),
    ("BALANCE_TRANSFER_AMOUNT_INVALID", "Invalid transfer amount"),
    (
        "BALANCE_TRANSFER_INSUFFICIENT_BALANCE",
        "Insufficient balance for this transfer",
    ),
    (
        "BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED",
        "Recipient balance would exceed the allowed limit",
    ),
    (
        "HOST_UNAVAILABLE",
        "Selected host is unavailable or has insufficient resources",
    ),
    (
        "HOST_NO_ONLINE",
        "No online hosts available, please test connection in node management",
    ),
    (
        "HOST_RESOURCES_NOT_SYNCED",
        "Host resources not synced, please click \"Test Connection\" in node management",
    ),
    (
        "HOST_NODE_GROUP_NO_HOSTS",
        "No available hosts bound to this package",
    ),
    (
        "HOST_RESOURCES_INSUFFICIENT",
        "All hosts have insufficient resources, please try later or choose another package",
    ),
    ("HOST_NAME_EXISTS", "Host name already exists"),
    ("HOST_ADDRESS_EXISTS", "Host connection address already exists"),
    (
        "HOST_ADDRESS_UNRESOLVABLE",
        "Panel could not resolve the host connection address",
    ),
    ("HOST_CERT_NOT_CONFIGURED", "Please configure certificate path first"),
    ("HOST_INVALID_CPU_MAX", "CPU max allowance cannot be negative"),
    (
        "HOST_INVALID_MEMORY_MAX",
        "Memory max cannot be negative or less than 256MB",
    ),
    (
        "HOST_INVALID_IPV6_MODE",
        "IPv6 mode must be 1 (route), 2 (NAT), or 3 (disabled)",
    ),
    (
        "HOST_IPV6_ROUTE_REQUIRES_CONFIG",
        "IPv6 route mode requires subnet and parent interface configuration",
    ),
    (
        "HOST_CPU_BELOW_USED",
        "CPU max allowance cannot be less than current usage by instances",
    ),
    (
        "HOST_MEMORY_BELOW_USED",
        "Memory max cannot be less than current usage by instances",
    ),
    (
        "HOST_INSTANCE_TYPE_MISMATCH",
        "Package instance type is not supported by the selected host",
    ),
    ("INSTANCE_STOP_REQUIRED", "Please stop the instance first"),
    ("INSTANCE_IMAGE_REQUIRED", "Please specify an image"),
    (
        "INSTANCE_IMAGE_UNAVAILABLE",
        "Selected image is not available on this host",
    ),
    ("INSTANCE_REBUILD_FAILED", "Instance rebuild failed"),
    ("INSTANCE_CLONE_FAILED", "Instance clone failed"),
    (
        "INSTANCE_IPV6_NOT_SUPPORTED",
        "Only NAT + IPv6 mode instances support IPv6 reassignment",
    ),
    (
        "INSTANCE_IPV6_REASSIGN_FAILED",
        "Failed to reassign IPv6 address",
    ),
    (
        "INSTANCE_NO_IPV4",
        "VM instance requires IPv4 address for port mapping",
    ),
    ("HOST_NO_IPV6_SUBNET", "Host has no IPv6 subnet configured"),
    (
        "IPV6_POOL_EXHAUSTED",
        "IPv6 address pool exhausted, please try again later",
    ),
    (
        "IPV6_REASSIGN_COOLDOWN",
        "IPv6 can only be reassigned once per day, please try again later",
    ),
    (
        "PORT_MAPPING_NAT_ONLY",
        "Port mapping is only supported in NAT or dual-stack mode",
    ),
    (
        "PORT_NO_AVAILABLE",
        "No available ports, please contact administrator",
    ),
    ("PORT_MAPPING_INVALID_ID", "Invalid instance or port mapping ID"),
    ("IMAGE_CREATE_FAILED", "Image creation failed"),
    ("IMAGE_UPDATE_FAILED", "Image update failed"),
    ("IMAGE_INVALID_HOST_ID", "Invalid image or host ID"),
    ("BACKUP_CREATE_FAILED", "Backup creation failed"),
    ("BACKUP_DELETE_FAILED", "Backup deletion failed"),
    ("BACKUP_EXPORT_FAILED", "Backup export failed"),
    (
        "BACKUP_QUOTA_NOT_SET",
        "Please set backup quota for this instance first",
    ),
    ("BACKUP_EXPORT_STATUS_INVALID", "Export task status is invalid"),
    ("CONFIG_INVALID_KEY", "Invalid configuration key"),
    (
        "CONFIG_INVALID_VALUE",
        "Configuration value must be a non-negative integer",
    ),
    (
        "SNAPSHOT_QUOTA_NOT_SET",
        "Please set snapshot quota for this instance first",
    ),
    (
        "PACKAGE_HAS_INSTANCES",
        "Package is in use by instances and cannot be deleted",
    ),
    ("RESOURCE_CPU_EXCEEDS_PACKAGE", "CPU configuration exceeds package limit"),
    (
        "RESOURCE_MEMORY_EXCEEDS_PACKAGE",
        "Memory configuration exceeds package limit",
    ),
    (
        "RESOURCE_DISK_EXCEEDS_PACKAGE",
        "Disk configuration exceeds package limit",
    ),
    ("QUOTA_CPU_INSUFFICIENT", "CPU quota insufficient"),
    ("QUOTA_MEMORY_INSUFFICIENT", "Memory quota insufficient"),
    ("QUOTA_DISK_INSUFFICIENT", "Disk quota insufficient"),
    ("QUOTA_INSTANCE_LIMIT_REACHED", "Instance limit reached"),
    ("QUOTA_HOST_LIMIT_REACHED", "Host limit reached"),
    ("QUOTA_PACKAGE_LIMIT_REACHED", "Package limit reached"),
    ("QUOTA_FRIEND_LIMIT_REACHED", "Friend limit reached"),
    (
        "QUOTA_PORT_BELOW_USED",
        "Port quota cannot be less than current usage",
    ),
    (
        "QUOTA_SNAPSHOT_BELOW_USED",
        "Snapshot quota cannot be less than current usage",
    ),
    (
        "QUOTA_BACKUP_BELOW_USED",
        "Backup quota cannot be less than current usage",
    ),
    ("QUOTA_PORT_TOTAL_EXCEEDED", "Total port quota exceeds user limit"),
    (
        "QUOTA_SNAPSHOT_TOTAL_EXCEEDED",
        "Total snapshot quota exceeds user limit",
    ),
    (
        "QUOTA_BACKUP_TOTAL_EXCEEDED",
        "Total backup quota exceeds user limit",
    ),
    ("IMAGE_NOT_SYNCED", "Image not synced to selected host"),
    (
        "IMAGE_SYNCING_CANNOT_DELETE",
        "Image is syncing on hosts and cannot be deleted",
    ),
    ("IMAGE_NO_HOSTS", "No available hosts, please add hosts first"),
    ("PORT_RANGE_INVALID", "Port must be within allowed range"),
    (
        "SNAPSHOT_MANUAL_FULL",
        "Manual snapshots have reached instance quota, cannot enable auto snapshot",
    ),
    ("SNAPSHOT_RETENTION_EXCEEDS", "Retention count exceeds available quota"),
    (
        "BACKUP_MANUAL_FULL",
        "Manual backups have reached instance quota, cannot enable auto backup",
    ),
    ("BACKUP_RETENTION_EXCEEDS", "Retention count exceeds available quota"),
    ("OAUTH_NOT_ENABLED", "This OAuth provider is not enabled"),
    ("STORAGE_CONFIG_NOT_FOUND", "Storage configuration not found"),
    (
        "STORAGE_CONFIG_CREATE_FAILED",
        "Failed to create storage configuration",
    ),
    (
        "STORAGE_CONFIG_UPDATE_FAILED",
        "Failed to update storage configuration",
    ),
    (
        "STORAGE_CONFIG_DELETE_FAILED",
        "Failed to delete storage configuration",
    ),
    ("STORAGE_TYPE_NOT_SUPPORTED", "Storage type not supported"),
    (
        "STORAGE_POOL_NOT_CONFIGURED",
        "No system disk storage pool configured on host",
    ),
    ("BACKUP_UPLOAD_TASK_NOT_FOUND", "Backup upload task not found"),
    (
        "BACKUP_UPLOAD_IN_PROGRESS",
        "A backup upload task is already in progress",
    ),
    ("BACKUP_UPLOAD_FAILED", "Backup upload failed"),
    (
        "CONFIG_DISK_CANNOT_SHRINK",
        "Disk size can only be increased, not decreased",
    ),
    ("CONFIG_NO_CHANGES", "No configuration changes provided"),
    (
        "CONFIG_UPDATE_FAILED",
        "Failed to update instance configuration",
    ),
    ("TRANSFER_NOT_FOUND", "Transfer request not found"),
    ("TRANSFER_TO_SELF", "Cannot transfer to yourself"),
    ("TRANSFER_TO_BANNED", "Cannot transfer to a banned user"),
    (
        "TRANSFER_ALREADY_PENDING",
        "This instance already has a pending transfer request",
    ),
    (
        "TRANSFER_NOT_PENDING",
        "Transfer request is not in pending status",
    ),
    (
        "TRANSFER_INVALID_STATUS",
        "Instance status does not allow transfer",
    ),
    ("TRANSFER_QUOTA_NOT_FOUND", "Target user quota not found"),
    ("TRANSFER_QUOTA_INSUFFICIENT", "Target user quota insufficient"),
    ("TRANSFER_INSTANCE_LOCKED", "Instance is locked due to pending transfer"),
    (
        "TRANSFER_INSUFFICIENT_BALANCE",
        "Insufficient balance for transfer fee",
    ),
    ("TRANSFER_HOST_DISABLED", "Transfer is disabled for this host"),
    ("INVALID_PARAMS", "Invalid parameters"),
    ("CANNOT_ADD_SELF", "Cannot add yourself as a friend"),
    ("ALREADY_FRIENDS", "You are already friends with this user"),
    ("FRIEND_REQUEST_PENDING", "A friend request is already pending"),
    ("FRIEND_REQUEST_NOT_FOUND", "Friend request not found"),
    (
        "FRIEND_REQUEST_NOT_PENDING",
        "Friend request is not in pending status",
    ),
    ("FRIENDSHIP_NOT_FOUND", "Friendship not found"),
    ("NOT_FRIENDS", "You are not friends with this user"),
    ("TARGET_FRIEND_QUOTA_FULL", "Target user friend quota is full"),
    ("CANNOT_SHARE_TO_SELF", "Cannot share package to yourself"),
    (
        "PACKAGE_ALREADY_SHARED",
        "Package is already shared to this user",
    ),
    ("SHARE_NOT_FOUND", "Share record not found"),
    ("SHARE_QUOTA_CPU_EXCEEDED", "Shared package CPU quota exceeded"),
    (
        "SHARE_QUOTA_MEMORY_EXCEEDED",
        "Shared package memory quota exceeded",
    ),
    (
        "SHARE_QUOTA_INSTANCES_EXCEEDED",
        "Shared package instance limit exceeded",
    ),
    ("EMAIL_VERIFICATION_DISABLED", "Email verification is not enabled"),
    (
        "EMAIL_CODE_REQUIRED",
        "Email verification code is required",
    ),
    ("INVALID_EMAIL_CODE", "Invalid or expired verification code"),
    (
        "TOO_MANY_VERIFICATION_REQUESTS",
        "Too many verification requests, please try again later",
    ),
    ("EMAIL_SEND_FAILED", "Failed to send verification email"),
    ("EMAIL_ALREADY_REGISTERED", "Email address is already registered"),
    (
        "EMAIL_DOMAIN_NOT_ALLOWED",
        "This email domain is not allowed for registration",
    ),
    ("MESSAGE_NOT_FOUND", "Message not found"),
    (
        "CHECKIN_NO_INSTANCE",
        "You need at least one instance to check in",
    ),
    ("CHECKIN_ALREADY_TODAY", "You have already checked in today"),
    ("REDEEM_ALREADY_TODAY", "You have already redeemed a code today"),
    ("REDEEM_CODE_NOT_FOUND", "Redeem code not found"),
    ("REDEEM_CODE_USED", "Redeem code has already been used"),
    ("REDEEM_CODE_EXPIRED", "Redeem code has expired"),
    (
        "REDEEM_CODE_SELF_ONLY",
        "This redeem code can only be used by its owner",
    ),
    ("REDEEM_CODE_DISABLED", "This redeem code has been disabled"),
    (
        "REDEEM_CODE_INVALID_FORMAT",
        "Invalid code format, only h- prefix codes are supported",
    ),
    (
        "REDEEM_CODE_EXHAUSTED",
        "This redeem code has reached its maximum usage limit",
    ),
    (
        "REDEEM_CODE_ALREADY_USED_BY_USER",
        "You have already used this redeem code",
    ),
    (
        "REDEEM_CODE_HOST_MISMATCH",
        "This redeem code can only be used on instances from the same host",
    ),
    (
        "REDEEM_CODE_BATCH_LIMIT",
        "You have already used a redeem code from this batch",
    ),
    (
        "REDEEM_EXCEEDS_PACKAGE_QUOTA",
        "Redeeming would exceed instance package quota",
    ),
    (
        "REDEEM_ALREADY_AT_LIMIT",
        "Instance resource is already at package limit",
    ),
    (
        "CHECKIN_CODE_PAID_INSTANCE",
        "Check-in redeem codes can only be used on free instances",
    ),
    ("COUPON_NOT_FOUND", "Official coupon not found"),
    ("COUPON_DISABLED", "This official coupon has been disabled"),
    ("COUPON_NOT_STARTED", "This official coupon is not active yet"),
    ("COUPON_EXPIRED", "This official coupon has expired"),
    (
        "COUPON_SCOPE_MISMATCH",
        "This official coupon does not apply to the selected package",
    ),
    (
        "COUPON_USER_LIMIT_REACHED",
        "You have reached the usage limit for this official coupon",
    ),
    (
        "COUPON_EXHAUSTED",
        "This official coupon has reached its total usage limit",
    ),
    ("COUPON_CODE_EXISTS", "Official coupon code already exists"),
    (
        "COUPON_IN_USE",
        "Used official coupons cannot be deleted, disable it instead",
    ),
    (
        "COUPON_INVALID_DISCOUNT",
        "Discount rate must be between 0 and 0.99",
    ),
    (
        "RESOURCE_POOL_INSUFFICIENT",
        "Insufficient resource pool balance",
    ),
    (
        "RESOURCE_POOL_KVM_CPU_MULTIPLE",
        "KVM instance CPU must be a multiple of 100",
    ),
    (
        "RESOURCE_POOL_KVM_MEMORY_MULTIPLE",
        "KVM instance memory must be a multiple of 128MB",
    ),
    (
        "RESOURCE_POOL_KVM_DISK_MULTIPLE",
        "KVM instance disk must be a multiple of 1GB (1024MB)",
    ),
    (
        "RESOURCE_POOL_VM_MUST_STOP",
        "KVM instance must be stopped to adjust memory or disk",
    ),
    (
        "RESOURCE_POOL_SYSTEM_CODE_REQUIRES_INSTANCE",
        "System redeem code requires an instance to be specified",
    ),
    ("INTERNAL_ERROR", "Internal server error"),
    ("VALIDATION_ERROR", "Validation error"),
    ("OPERATION_NOT_ALLOWED", "Operation not allowed"),
    ("RESOURCE_EXISTS", "Resource already exists"),
    ("UPSTREAM_ERROR", "Upstream service error"),
    ("INSUFFICIENT_BALANCE", "Insufficient balance"),
    // Ad hoc codes
    ("AGENT_AUTH_REQUIRED", "Agent authentication required"),
    ("AGENT_AUTH_INVALID", "Agent authentication invalid"),
    ("AGENT_AUTH_EXPIRED", "Agent authentication expired"),
    ("AGENT_BODY_HASH_MISMATCH", "Agent request body hash mismatch"),
    ("AGENT_DISABLED", "Agent is disabled"),
    ("AGENT_SECRET_INVALID", "Agent secret invalid"),
    ("AGENT_SIGNATURE_INVALID", "Agent signature invalid"),
    ("AGENT_NONCE_REPLAY", "Agent nonce replay detected"),
    ("RESOURCE_BUSY", "Resource is busy, please retry"),
    ("LOGOUT_FAILED", "Logout failed"),
    ("TURNSTILE_NOT_CONFIGURED", "Turnstile is not configured"),
    ("TURNSTILE_TOKEN_MISSING", "Turnstile token is missing"),
    ("FILE_TOO_LARGE", "Uploaded file is too large"),
    ("IP_LIMIT_EXCEEDED", "IP limit exceeded"),
    ("USER_ONLY", "This feature is for regular users only"),
    ("SESSION_INVALIDATED", "Session expired"),
    ("NOT_PORTED", "This module is not yet ported to the Rust server"),
];

/// API error carrying the wire shape `{ error, code, details?, retryAfter? }`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    /// The `error` field. Normally message(code); routes may override with a
    /// custom message exactly like the TS server does inline.
    pub error: String,
    pub details: Option<String>,
    pub retry_after: Option<String>,
    /// Set when a serialization/deadlock retry is appropriate (balance tx loop).
    pub retryable: bool,
    /// The TS server sends bare `{ error }` (no `code`) for generic 401s; this
    /// flag reproduces that shape exactly.
    pub omit_code: bool,
}

impl ApiError {
    pub fn new(code: &str, status: StatusCode) -> Self {
        let error = message(code).unwrap_or(code).to_string();
        Self {
            status,
            code: code.to_string(),
            error,
            details: None,
            retry_after: None,
            retryable: false,
            omit_code: false,
        }
    }

    pub fn with_message(code: &str, status: StatusCode, error: impl Into<String>) -> Self {
        Self {
            status,
            code: code.to_string(),
            error: error.into(),
            details: None,
            retry_after: None,
            retryable: false,
            omit_code: false,
        }
    }

    /// `{ error }` without a code field (TS: reply.code(401).send({error:'Unauthorized'})).
    pub fn bare(status: StatusCode, error: impl Into<String>) -> Self {
        Self {
            status,
            code: String::new(),
            error: error.into(),
            details: None,
            retry_after: None,
            retryable: false,
            omit_code: true,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn with_retry_after(mut self, seconds: impl std::fmt::Display) -> Self {
        self.retry_after = Some(seconds.to_string());
        self
    }

    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn is_serialization_conflict(&self) -> bool {
        self.retryable
    }

    // ---- Common constructors (mirror TS route call sites) ----

    pub fn bad_request(code: &str) -> Self {
        Self::new(code, StatusCode::BAD_REQUEST)
    }

    pub fn unauthorized() -> Self {
        Self::bare(StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    pub fn unauthorized_code(code: &str) -> Self {
        Self::new(code, StatusCode::UNAUTHORIZED)
    }

    pub fn session_invalidated() -> Self {
        Self::new(code::SESSION_INVALIDATED, StatusCode::UNAUTHORIZED)
    }

    pub fn account_banned() -> Self {
        Self::new(code::ACCOUNT_BANNED, StatusCode::UNAUTHORIZED)
    }

    pub fn admin_required() -> Self {
        Self::new(code::ADMIN_REQUIRED, StatusCode::FORBIDDEN)
    }

    pub fn user_only() -> Self {
        Self::new(code::USER_ONLY, StatusCode::FORBIDDEN)
    }

    pub fn forbidden(code: &str) -> Self {
        Self::new(code, StatusCode::FORBIDDEN)
    }

    pub fn not_found(code: &str) -> Self {
        Self::new(code, StatusCode::NOT_FOUND)
    }

    pub fn conflict(code: &str) -> Self {
        Self::new(code, StatusCode::CONFLICT)
    }

    pub fn resource_busy() -> Self {
        Self::new(code::RESOURCE_BUSY, StatusCode::CONFLICT).with_retry_after(1)
    }

    pub fn validation(error: impl Into<String>) -> Self {
        Self::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, error)
    }

    pub fn too_many_requests(retry_after_seconds: u64) -> Self {
        Self::with_message(
            "RATE_LIMITED",
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests, please try again later",
        )
        .with_retry_after(retry_after_seconds)
    }

    /// Production hides 5xx messages exactly like the TS setErrorHandler.
    pub fn internal(message: impl std::fmt::Display) -> Self {
        let is_production = crate::config::runtime_is_production();
        let error = if is_production {
            "Internal server error".to_string()
        } else {
            message.to_string()
        };
        Self::with_message(code::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR, error)
    }

    /// Map a sqlx error to the standard 500 shape.
    pub fn from_sql(err: sqlx::Error) -> Self {
        let is_production = crate::config::runtime_is_production();
        let detail = if is_production {
            None
        } else {
            Some(format!("{err}"))
        };
        let mut e = Self::internal("database error");
        if let Some(d) = detail {
            e = e.with_details(d);
        }
        e
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::from_sql(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "error": self.error,
        });
        if !self.omit_code {
            body["code"] = json!(self.code);
        }
        if let Some(details) = &self.details {
            body["details"] = json!(details);
        }
        if let Some(retry_after) = &self.retry_after {
            body["retryAfter"] = json!(retry_after);
        }
        let mut response = (self.status, Json(body)).into_response();
        if let Some(retry_after) = &self.retry_after {
            if let Ok(value) = retry_after.parse::<u64>() {
                response.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from(value),
                );
            }
        }
        response
    }
}
