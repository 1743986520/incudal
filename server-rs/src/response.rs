//! Response-building helpers matching the TS serialization conventions:
//! - Decimal money  -> JSON number via Number() (f64)
//! - BigInt bytes   -> JSON string
//! - pagination     -> parsePagination() semantics

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Decimal -> JSON number, exactly like the TS `Number(decimal)` boundary
/// conversions (including their f64 precision behaviour).
pub fn num(value: Decimal) -> serde_json::Number {
    // JS prints integral numbers without a decimal point (Number(123) -> "123",
    // not "123.0"), so integral Decimals must serialize as JSON integers.
    if value.is_integer() {
        if let Some(i) = value.to_i64() {
            return serde_json::Number::from(i);
        }
    }
    serde_json::Number::from_f64(value.to_f64().unwrap_or(0.0))
        .unwrap_or_else(|| serde_json::Number::from(0))
}

pub fn num_opt(value: Option<Decimal>) -> Value {
    match value {
        Some(v) => json!(num(v)),
        None => Value::Null,
    }
}

/// BigInt byte counter -> JSON string (BigInt as string contract).
pub fn big(value: i64) -> Value {
    json!(value.to_string())
}

pub fn big_opt(value: Option<i64>) -> Value {
    match value {
        Some(v) => json!(v.to_string()),
        None => Value::Null,
    }
}

/// bigint column that may come back as NUMERIC from raw SQL aggregates.
pub fn big_from_decimal(value: Decimal) -> Value {
    json!(value.to_string())
}

#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    pub page: i64,
    pub page_size: i64,
    pub skip: i64,
    pub take: i64,
}

/// Mirrors db/pagination.ts parsePagination: invalid/zero/negative input falls
/// back to defaults; page starts at 1.
pub fn parse_pagination(
    params: &HashMap<String, String>,
    default_page_size: i64,
    max_page_size: Option<i64>,
) -> Pagination {
    let page = params
        .get("page")
        .and_then(|v| parse_int_prefix(v))
        .filter(|v| *v >= 1)
        .unwrap_or(1);
    let mut page_size = params
        .get("pageSize")
        .and_then(|v| parse_int_prefix(v))
        .filter(|v| *v >= 1)
        .unwrap_or(default_page_size);
    if let Some(max) = max_page_size {
        if page_size > max {
            page_size = max;
        }
    }
    Pagination {
        page,
        page_size,
        skip: (page - 1) * page_size,
        take: page_size,
    }
}

/// JS parseInt-style leading-integer parse.
fn parse_int_prefix(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let bytes = s.as_bytes();
    let mut end = 0usize;
    if bytes.first().map(|b| *b == b'-' || *b == b'+').unwrap_or(false) {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return None;
    }
    s[..end].parse().ok()
}

/// Standard envelope for list responses used across the TS routes:
/// `{ items, total, page, pageSize }` (routes vary slightly; keep helpers local
/// to each route when the shape differs).
pub fn list_envelope(items: Vec<Value>, total: i64, pagination: &Pagination) -> Value {
    json!({
        "items": items,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })
}
