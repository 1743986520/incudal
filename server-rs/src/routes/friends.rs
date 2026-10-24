//! 好友系统 API 路由 — port of server/src/routes/friends.ts (mounted at /api/friends).
//!
//! All endpoints require a regular (non-admin) user: fastify.authenticateUser
//! maps to the `UserOnlyAuth` extractor.
//!
//! Deviation (reported): sendNotification() in TS also fans out to external
//! channels (Telegram/Discord/webhook/email). Only the always-created inbox
//! message part is ported here (see create_inbox_notification in users.rs).

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::routes::users::{create_inbox_notification, create_log};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_friends))
        .route("/request", post(send_request))
        .route("/request/{id}", delete(cancel_request))
        .route("/requests", get(pending_requests))
        .route("/requests/sent", get(sent_requests))
        .route("/history", get(request_history))
        .route("/search", get(search_user))
        .route("/{id}/accept", post(accept_request))
        .route("/{id}/reject", post(reject_request))
        .route("/{id}/resources", get(friend_resources))
        .route("/{id}", delete(remove_friend))
}

// ===========================================================================
// serialization helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn iso_opt(value: Option<DateTime<Utc>>) -> Value {
    match value {
        Some(v) => json!(iso(v)),
        None => Value::Null,
    }
}

/// TS `Number(id)` param parse: non-numeric -> 400 INVALID_ID.
fn parse_path_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

// ===========================================================================
// db helpers (port of db/friendships.ts)
// ===========================================================================

#[derive(Debug, FromRow)]
struct FriendshipRow {
    id: i32,
    user_id: i32,
    friend_id: i32,
    status: String,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
}

impl FriendshipRow {
    /// Full friendship row as Prisma serializes it (camelCase, dates as ISO).
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "userId": self.user_id,
            "friendId": self.friend_id,
            "status": self.status,
            "remark": self.remark,
            "createdAt": iso(self.created_at),
            "acceptedAt": iso_opt(self.accepted_at),
            "rejectedAt": iso_opt(self.rejected_at),
        })
    }
}

/// Column list + `::text` casts for the FriendshipStatus enum reads.
const FRIENDSHIP_COLS: &str = "id, user_id, friend_id, status::text AS status, remark, \
     created_at, accepted_at, rejected_at";

async fn fetch_friendship_row(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<FriendshipRow>, ApiError> {
    let row = sqlx::query_as::<_, FriendshipRow>(&format!(
        "SELECT {FRIENDSHIP_COLS} FROM friendships WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// Mirrors getFriendshipById(): friendship row plus both user profiles
/// (su_* = initiator/user_id side, ru_* = receiver/friend_id side).
#[derive(Debug, FromRow)]
struct FriendshipWithUsers {
    id: i32,
    user_id: i32,
    friend_id: i32,
    status: String,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
    su_id: i32,
    su_username: String,
    su_email: Option<String>,
    su_avatar_style: String,
    su_avatar_badge_id: Option<String>,
    ru_id: i32,
    ru_username: String,
    ru_email: Option<String>,
    ru_avatar_style: String,
    ru_avatar_badge_id: Option<String>,
}

async fn get_friendship_by_id(
    state: &SharedAppState,
    friendship_id: i32,
) -> Result<Option<FriendshipWithUsers>, ApiError> {
    let row = sqlx::query_as::<_, FriendshipWithUsers>(
        "SELECT f.id, f.user_id, f.friend_id, f.status::text AS status, f.remark, \
                f.created_at, f.accepted_at, f.rejected_at, \
                su.id AS su_id, su.username AS su_username, su.email AS su_email, \
                su.avatar_style AS su_avatar_style, su.avatar_badge_id AS su_avatar_badge_id, \
                ru.id AS ru_id, ru.username AS ru_username, ru.email AS ru_email, \
                ru.avatar_style AS ru_avatar_style, ru.avatar_badge_id AS ru_avatar_badge_id \
         FROM friendships f \
         JOIN users su ON su.id = f.user_id \
         JOIN users ru ON ru.id = f.friend_id \
         WHERE f.id = $1",
    )
    .bind(friendship_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

#[derive(Debug, FromRow)]
struct UserBrief {
    id: i32,
    username: String,
    email: Option<String>,
    avatar_style: String,
    avatar_badge_id: Option<String>,
}

/// Mirrors searchUserByUsername(): case-insensitive exact match, excludes self,
/// only active users.
async fn search_user_by_username(
    state: &SharedAppState,
    username: &str,
    exclude_user_id: i32,
) -> Result<Option<UserBrief>, ApiError> {
    let row = sqlx::query_as::<_, UserBrief>(
        "SELECT id, username, email, avatar_style, avatar_badge_id FROM users \
         WHERE LOWER(username) = LOWER($1) AND id <> $2 AND status = 'active' LIMIT 1",
    )
    .bind(username)
    .bind(exclude_user_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn are_friends(state: &SharedAppState, user_a: i32, user_b: i32) -> Result<bool, ApiError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM friendships WHERE status = 'accepted' \
         AND ((user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)) LIMIT 1",
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

/// TS `remark || null` — empty string becomes NULL.
fn clean_remark(remark: Option<&str>) -> Option<&str> {
    remark.filter(|r| !r.is_empty())
}

// ===========================================================================
// GET / — 好友列表
// ===========================================================================

#[derive(Debug, FromRow)]
struct FriendListRow {
    friendship_id: i32,
    f_user_id: i32,
    f_created_at: DateTime<Utc>,
    f_accepted_at: Option<DateTime<Utc>>,
    u_id: i32,
    username: String,
    email: Option<String>,
    avatar_style: String,
    avatar_badge_id: Option<String>,
    host_count: i64,
    instance_count: i64,
}

async fn list_friends(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    // Mirrors getFriendList(): accepted relations in both directions, the other
    // party's profile, their total host count and non-deleted instance count.
    let rows = sqlx::query_as::<_, FriendListRow>(
        "SELECT f.id AS friendship_id, f.user_id AS f_user_id, \
                f.created_at AS f_created_at, f.accepted_at AS f_accepted_at, \
                u.id AS u_id, u.username, u.email, u.avatar_style, u.avatar_badge_id, \
                (SELECT COUNT(*) FROM hosts h WHERE h.user_id = u.id) AS host_count, \
                (SELECT COUNT(*) FROM instances i WHERE i.user_id = u.id \
                   AND i.status <> 'deleted') AS instance_count \
         FROM friendships f \
         JOIN users u ON u.id = (CASE WHEN f.user_id = $1 THEN f.friend_id ELSE f.user_id END) \
         WHERE f.status = 'accepted' AND (f.user_id = $1 OR f.friend_id = $1) \
         ORDER BY f.accepted_at DESC",
    )
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let friends: Vec<Value> = rows
        .iter()
        .map(|r| {
            let initiated_by_me = r.f_user_id == user.0.id;
            json!({
                "id": r.u_id,
                "friendshipId": r.friendship_id,
                "friendId": r.u_id,
                "username": r.username,
                "email": r.email,
                "avatarStyle": r.avatar_style,
                "avatarBadgeId": r.avatar_badge_id,
                "status": "accepted",
                "createdAt": iso(r.f_created_at),
                "acceptedAt": iso_opt(r.f_accepted_at),
                "initiatedByMe": initiated_by_me,
                "hostCount": r.host_count,
                "instanceCount": r.instance_count,
            })
        })
        .collect();

    Ok(Json(json!({ "friends": friends })))
}

// ===========================================================================
// POST /request — 发送好友请求
// ===========================================================================

#[derive(Deserialize)]
struct SendRequestBody {
    username: String,
    remark: Option<String>,
}

async fn send_request(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<SendRequestBody>,
) -> Result<Json<Value>, ApiError> {
    // 搜索目标用户
    let target = search_user_by_username(&state, &body.username, user.0.id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // Mirrors db.sendFriendRequest()
    let result: FriendshipRow = {
        let existing = sqlx::query_as::<_, FriendshipRow>(&format!(
            "SELECT {FRIENDSHIP_COLS} FROM friendships \
             WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1) LIMIT 1"
        ))
        .bind(user.0.id)
        .bind(target.id)
        .fetch_optional(&state.db)
        .await?;

        if let Some(existing) = existing {
            if existing.status == "accepted" {
                return Err(ApiError::bad_request(code::ALREADY_FRIENDS));
            }
            if existing.status == "pending" {
                // 如果对方已经向我发送了请求，直接接受
                if existing.user_id == target.id && existing.friend_id == user.0.id {
                    accept_friendship_by_id(&state, existing.id).await?
                } else {
                    return Err(ApiError::bad_request(code::FRIEND_REQUEST_PENDING));
                }
            } else if existing.status == "rejected" {
                // 如果之前被拒绝过，允许重新发送请求
                reopen_friendship_request(&state, existing.id, clean_remark(body.remark.as_deref()))
                    .await?
            } else {
                // status 'removed': the TS code falls through to
                // prisma.friendship.create which hits the (user_id, friend_id)
                // unique constraint and surfaces as a 500 INTERNAL_ERROR.
                return Err(ApiError::internal(
                    "friendship already exists (unique constraint on user_id+friend_id)",
                ));
            }
        } else {
            sqlx::query_as::<_, FriendshipRow>(&format!(
                "INSERT INTO friendships (user_id, friend_id, status, remark) \
                 VALUES ($1, $2, 'pending'::\"FriendshipStatus\", $3) RETURNING {FRIENDSHIP_COLS}"
            ))
            .bind(user.0.id)
            .bind(target.id)
            .bind(clean_remark(body.remark.as_deref()))
            .fetch_one(&state.db)
            .await?
        }
    };

    if result.status == "accepted" {
        create_log(
            &state,
            user.0.id,
            "friend",
            "friend.request_auto_accepted",
            &format!("Auto accepted friend request with user \"{}\"", target.username),
            "success",
        )
        .await;

        // 通知对方：他之前发的请求被接受了
        create_inbox_notification(
            &state,
            target.id,
            "friend_accepted",
            "✅ 好友申请已通过",
            &format!(
                "用户「{}」已接受您的好友申请，您们现在是好友了",
                user.0.username
            ),
            json!({ "toUsername": user.0.username }),
        )
        .await;
        // 通知当前用户：你们成为好友了（对方之前发过请求）
        create_inbox_notification(
            &state,
            user.0.id,
            "friend_request",
            "👥 新的好友申请",
            &format!(
                "用户「{}」向您发送了好友申请，请前往好友管理页面处理",
                target.username
            ),
            json!({ "fromUsername": target.username }),
        )
        .await;

        return Ok(Json(json!({
            "message": "好友添加成功（对方已向您发送请求）",
            "friendship": result.to_json(),
        })));
    }

    create_log(
        &state,
        user.0.id,
        "friend",
        "friend.request_sent",
        &format!("Sent friend request to user \"{}\"", target.username),
        "success",
    )
    .await;

    // 通知目标用户收到好友请求
    create_inbox_notification(
        &state,
        target.id,
        "friend_request",
        "👥 新的好友申请",
        &format!(
            "用户「{}」向您发送了好友申请，请前往好友管理页面处理",
            user.0.username
        ),
        json!({ "fromUsername": user.0.username }),
    )
    .await;

    Ok(Json(json!({
        "message": "好友请求已发送",
        "request": { "id": result.id },
    })))
}

/// `UPDATE ... RETURNING` for acceptFriendRequest.
async fn accept_friendship_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<FriendshipRow, ApiError> {
    sqlx::query_as::<_, FriendshipRow>(&format!(
        "UPDATE friendships SET status = 'accepted'::\"FriendshipStatus\", accepted_at = now() \
         WHERE id = $1 RETURNING {FRIENDSHIP_COLS}"
    ))
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::from_sql)
}

/// `UPDATE ... RETURNING` for the rejected -> pending re-open path.
async fn reopen_friendship_request(
    state: &SharedAppState,
    id: i32,
    remark: Option<&str>,
) -> Result<FriendshipRow, ApiError> {
    sqlx::query_as::<_, FriendshipRow>(&format!(
        "UPDATE friendships SET status = 'pending'::\"FriendshipStatus\", remark = $2, \
         rejected_at = NULL WHERE id = $1 RETURNING {FRIENDSHIP_COLS}"
    ))
    .bind(id)
    .bind(remark)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::from_sql)
}

// ===========================================================================
// GET /requests — 收到的待处理好友请求
// ===========================================================================

#[derive(Debug, FromRow)]
struct FriendRequestRow {
    id: i32,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    u_id: i32,
    username: String,
    email: Option<String>,
    avatar_style: String,
    avatar_badge_id: Option<String>,
}

fn friend_request_json(r: &FriendRequestRow) -> Value {
    json!({
        "id": r.id,
        "userId": r.u_id,
        "username": r.username,
        "email": r.email,
        "avatarStyle": r.avatar_style,
        "avatarBadgeId": r.avatar_badge_id,
        "remark": r.remark,
        "createdAt": iso(r.created_at),
    })
}

async fn pending_requests(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, FriendRequestRow>(
        "SELECT f.id, f.remark, f.created_at, u.id AS u_id, u.username, u.email, \
                u.avatar_style, u.avatar_badge_id \
         FROM friendships f JOIN users u ON u.id = f.user_id \
         WHERE f.friend_id = $1 AND f.status = 'pending' \
         ORDER BY f.created_at DESC",
    )
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let requests: Vec<Value> = rows.iter().map(friend_request_json).collect();
    Ok(Json(json!({ "requests": requests })))
}

// ===========================================================================
// GET /requests/sent — 已发送的待处理好友请求
// ===========================================================================

async fn sent_requests(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, FriendRequestRow>(
        "SELECT f.id, f.remark, f.created_at, u.id AS u_id, u.username, u.email, \
                u.avatar_style, u.avatar_badge_id \
         FROM friendships f JOIN users u ON u.id = f.friend_id \
         WHERE f.user_id = $1 AND f.status = 'pending' \
         ORDER BY f.created_at DESC",
    )
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let requests: Vec<Value> = rows.iter().map(friend_request_json).collect();
    Ok(Json(json!({ "requests": requests })))
}

// ===========================================================================
// DELETE /request/:id — 取消已发送的好友请求
// ===========================================================================

async fn cancel_request(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let request_id = parse_path_id(&id)?;

    // Mirrors db.cancelFriendRequest()
    let request = fetch_friendship_row(&state, request_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::NOT_FOUND).with_details("请求不存在"))?;

    // 只有发起者才能取消
    if request.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN).with_details("无权取消此请求"));
    }

    if request.status != "pending" {
        return Err(ApiError::bad_request(code::FRIEND_REQUEST_NOT_PENDING));
    }

    sqlx::query("DELETE FROM friendships WHERE id = $1")
        .bind(request_id)
        .execute(&state.db)
        .await?;

    create_log(
        &state,
        user.0.id,
        "friend",
        "friend.request_cancelled",
        &format!("Cancelled friend request #{request_id}"),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "已取消好友请求" })))
}

// ===========================================================================
// POST /:id/accept — 接受好友请求
// ===========================================================================

async fn accept_request(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let request_id = parse_path_id(&id)?;

    // 获取请求信息
    let friendship = get_friendship_by_id(&state, request_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::FRIEND_REQUEST_NOT_FOUND))?;

    // Mirrors db.acceptFriendRequest()
    if friendship.friend_id != user.0.id {
        // 只有接收者才能接受
        return Err(ApiError::forbidden(code::FORBIDDEN).with_details("无权处理此请求"));
    }
    if friendship.status != "pending" {
        return Err(ApiError::bad_request(code::FRIEND_REQUEST_NOT_PENDING));
    }

    let result = accept_friendship_by_id(&state, request_id).await?;

    create_log(
        &state,
        user.0.id,
        "friend",
        "friend.request_accepted",
        &format!(
            "Accepted friend request from user \"{}\"",
            friendship.su_username
        ),
        "success",
    )
    .await;

    // 通知发送者请求已被接受
    create_inbox_notification(
        &state,
        friendship.user_id,
        "friend_accepted",
        "✅ 好友申请已通过",
        &format!(
            "用户「{}」已接受您的好友申请，您们现在是好友了",
            user.0.username
        ),
        json!({ "toUsername": user.0.username }),
    )
    .await;

    Ok(Json(json!({
        "message": "已接受好友请求",
        "friendship": result.to_json(),
    })))
}

// ===========================================================================
// POST /:id/reject — 拒绝好友请求
// ===========================================================================

async fn reject_request(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let request_id = parse_path_id(&id)?;

    // 获取请求信息用于日志
    let friendship = get_friendship_by_id(&state, request_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::FRIEND_REQUEST_NOT_FOUND))?;

    // Mirrors db.rejectFriendRequest()
    if friendship.friend_id != user.0.id {
        // 只有接收者才能拒绝
        return Err(ApiError::forbidden(code::FORBIDDEN).with_details("无权处理此请求"));
    }
    if friendship.status != "pending" {
        return Err(ApiError::bad_request(code::FRIEND_REQUEST_NOT_PENDING));
    }

    sqlx::query_as::<_, FriendshipRow>(&format!(
        "UPDATE friendships SET status = 'rejected'::\"FriendshipStatus\", rejected_at = now() \
         WHERE id = $1 RETURNING {FRIENDSHIP_COLS}"
    ))
    .bind(request_id)
    .fetch_one(&state.db)
    .await?;

    create_log(
        &state,
        user.0.id,
        "friend",
        "friend.request_rejected",
        &format!(
            "Rejected friend request from user \"{}\"",
            friendship.su_username
        ),
        "success",
    )
    .await;

    // 通知发送者请求已被拒绝
    create_inbox_notification(
        &state,
        friendship.user_id,
        "friend_rejected",
        "❌ 好友申请被拒绝",
        &format!("用户「{}」拒绝了您的好友申请", user.0.username),
        json!({ "toUsername": user.0.username }),
    )
    .await;

    Ok(Json(json!({ "message": "已拒绝好友请求" })))
}

// ===========================================================================
// DELETE /:id — 删除好友
// ===========================================================================

async fn remove_friend(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let friendship_id = parse_path_id(&id)?;

    // 获取好友关系信息
    let friendship = get_friendship_by_id(&state, friendship_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::FRIENDSHIP_NOT_FOUND))?;

    // Mirrors db.removeFriend(): 任一方都可以删除好友
    if friendship.user_id != user.0.id && friendship.friend_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN).with_details("无权删除此好友"));
    }

    // 确定对方用户信息用于日志和通知
    let i_am_initiator = friendship.user_id == user.0.id;
    let friend_username = if i_am_initiator {
        &friendship.ru_username
    } else {
        &friendship.su_username
    };
    let friend_user_id = if i_am_initiator {
        friendship.friend_id
    } else {
        friendship.user_id
    };

    // 不删除记录，而是更新状态为 removed，以保留历史记录
    sqlx::query(
        "UPDATE friendships SET status = 'removed'::\"FriendshipStatus\" WHERE id = $1",
    )
    .bind(friendship_id)
    .execute(&state.db)
    .await?;

    create_log(
        &state,
        user.0.id,
        "friend",
        "friend.removed",
        &format!("Removed friend \"{friend_username}\""),
        "success",
    )
    .await;

    // 通知被删除的好友
    create_inbox_notification(
        &state,
        friend_user_id,
        "friend_removed",
        "💔 好友关系已解除",
        &format!("用户「{}」已将您从好友列表中移除", user.0.username),
        json!({ "fromUsername": user.0.username }),
    )
    .await;

    Ok(Json(json!({ "message": "已删除好友" })))
}

// ===========================================================================
// GET /history — 好友请求历史记录
// ===========================================================================

#[derive(Debug, FromRow)]
struct HistoryRow {
    id: i32,
    f_user_id: i32,
    status: String,
    remark: Option<String>,
    f_created_at: DateTime<Utc>,
    f_accepted_at: Option<DateTime<Utc>>,
    f_rejected_at: Option<DateTime<Utc>>,
    u_id: i32,
    username: String,
    email: Option<String>,
    avatar_style: String,
    avatar_badge_id: Option<String>,
}

#[derive(Deserialize, Default)]
struct HistoryQuery {
    filter: Option<String>,
}

async fn request_history(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    // filter: 'accepted' | 'rejected' | 'removed' | 'all' (default: all three)
    let status_filter = match query.filter.as_deref() {
        Some("accepted") => "= 'accepted'",
        Some("rejected") => "= 'rejected'",
        Some("removed") => "= 'removed'",
        _ => "IN ('accepted', 'rejected', 'removed')",
    };

    let sql = format!(
        "SELECT f.id, f.user_id AS f_user_id, f.status::text AS status, f.remark, \
                f.created_at AS f_created_at, f.accepted_at AS f_accepted_at, \
                f.rejected_at AS f_rejected_at, \
                u.id AS u_id, u.username, u.email, u.avatar_style, u.avatar_badge_id \
         FROM friendships f \
         JOIN users u ON u.id = (CASE WHEN f.user_id = $1 THEN f.friend_id ELSE f.user_id END) \
         WHERE f.status {status_filter} AND (f.friend_id = $1 OR f.user_id = $1) \
         ORDER BY f.created_at DESC"
    );

    let rows = sqlx::query_as::<_, HistoryRow>(&sql)
        .bind(user.0.id)
        .fetch_all(&state.db)
        .await?;

    let history: Vec<Value> = rows
        .iter()
        .map(|r| {
            let initiated_by_me = r.f_user_id == user.0.id;
            json!({
                "id": r.id,
                "userId": r.u_id,
                "username": r.username,
                "email": r.email,
                "avatarStyle": r.avatar_style,
                "avatarBadgeId": r.avatar_badge_id,
                "remark": r.remark,
                "status": r.status,
                "createdAt": iso(r.f_created_at),
                "acceptedAt": iso_opt(r.f_accepted_at),
                "rejectedAt": iso_opt(r.f_rejected_at),
                "initiatedByMe": initiated_by_me,
            })
        })
        .collect();

    Ok(Json(json!({ "history": history })))
}

// ===========================================================================
// GET /search — 搜索用户（用于添加好友）
// ===========================================================================

#[derive(Deserialize)]
struct SearchQuery {
    username: Option<String>,
}

async fn search_user(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    // Fastify schema requires username (minLength 1)
    let username = match query.username.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => return Err(ApiError::bad_request(code::INVALID_PARAMS)),
    };

    let target = search_user_by_username(&state, username, user.0.id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND).with_details("用户不存在"))?;

    // 检查是否已是好友
    let is_friend = are_friends(&state, user.0.id, target.id).await?;

    Ok(Json(json!({
        "user": {
            "id": target.id,
            "username": target.username,
            "avatarStyle": target.avatar_style,
            "isFriend": is_friend,
        }
    })))
}

// ===========================================================================
// GET /:id/resources — 获取好友的资源统计
// ===========================================================================

async fn friend_resources(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let friendship_id = parse_path_id(&id)?;

    let friendship = get_friendship_by_id(&state, friendship_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::NOT_FOUND).with_details("好友关系不存在"))?;

    // 验证权限
    if friendship.user_id != user.0.id && friendship.friend_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 确定好友的用户ID
    let friend_user_id = if friendship.user_id == user.0.id {
        friendship.friend_id
    } else {
        friendship.user_id
    };

    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM hosts WHERE user_id = $1), \
                (SELECT COUNT(*) FROM packages WHERE user_id = $1)",
    )
    .bind(friend_user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "resources": {
            "hosts": counts.0,
            "images": 0, // 镜像是节点级别的，不是用户级别
            "packages": counts.1,
        }
    })))
}
