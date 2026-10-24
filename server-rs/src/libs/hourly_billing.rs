//! 按小时计费定价计算 — port of server/src/lib/hourly-billing.ts (pure math +
//! snapshot parse; money entirely in Decimal, snapshots serialized toFixed(8)).

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct HourlyPricing {
    pub cpu_unit_percent: i64,
    pub memory_unit_mb: i64,
    pub disk_unit_mb: i64,
    pub min_cpu: i64,
    pub min_memory_mb: i64,
    pub min_disk_mb: i64,
    pub cpu_price_per_unit: Decimal,
    pub memory_price_per_unit: Decimal,
    pub disk_price_per_unit: Decimal,
    pub reserve_quantum: Decimal,
}

#[derive(Debug, Clone, Copy)]
pub struct HourlyResources {
    pub cpu: i64,
    pub memory: i64,
    pub disk: i64,
}

pub struct HourlyBreakdown {
    pub cpu_units: f64,
    pub memory_units: f64,
    pub disk_units: f64,
    pub cpu_amount: Decimal,
    pub memory_amount: Decimal,
    pub disk_amount: Decimal,
    pub hourly_price: Decimal,
}

/// snapshot strings carry 8-dp fixed decimals.
fn dec_from_fixed8(value: &str) -> Option<Decimal> {
    Decimal::from_str_exact(value).ok()
}

/// hourlyPricingFromPackagePlan — from package_plans hourly_* columns.
pub fn hourly_pricing_from_package_plan(row: &PlanHourlyRow) -> HourlyPricing {
    HourlyPricing {
        cpu_unit_percent: row.hourly_cpu_unit_percent,
        memory_unit_mb: row.hourly_memory_unit_mb,
        disk_unit_mb: row.hourly_disk_unit_mb,
        min_cpu: row.hourly_min_cpu,
        min_memory_mb: row.hourly_min_memory_mb,
        min_disk_mb: row.hourly_min_disk_mb,
        cpu_price_per_unit: row.hourly_cpu_price_per_unit,
        memory_price_per_unit: row.hourly_memory_price_per_unit,
        disk_price_per_unit: row.hourly_disk_price_per_unit,
        reserve_quantum: row.hourly_reserve_quantum,
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct PlanHourlyRow {
    pub id: i32,
    pub package_id: i32,
    pub billing_mode: String,
    pub is_active: bool,
    pub is_sold_out: bool,
    pub hourly_cpu_unit_percent: i64,
    pub hourly_memory_unit_mb: i64,
    pub hourly_disk_unit_mb: i64,
    pub hourly_min_cpu: i64,
    pub hourly_min_memory_mb: i64,
    pub hourly_min_disk_mb: i64,
    pub hourly_cpu_price_per_unit: Decimal,
    pub hourly_memory_price_per_unit: Decimal,
    pub hourly_disk_price_per_unit: Decimal,
    pub hourly_reserve_quantum: Decimal,
}

pub const PLAN_HOURLY_COLUMNS: &str = "id, package_id, billing_mode::text AS billing_mode, is_active, is_sold_out, \
    hourly_cpu_unit_percent, hourly_memory_unit_mb, hourly_disk_unit_mb, hourly_min_cpu, \
    hourly_min_memory_mb, hourly_min_disk_mb, hourly_cpu_price_per_unit, \
    hourly_memory_price_per_unit, hourly_disk_price_per_unit, hourly_reserve_quantum";

/// hourlyPricingFromSnapshot — validate the stored JSON without trusting shape.
pub fn hourly_pricing_from_snapshot(value: &Value) -> Option<HourlyPricing> {
    let snapshot = value.as_object()?;
    let int_field = |key: &str| -> Option<i64> {
        snapshot.get(key).and_then(Value::as_i64).filter(|v| *v > 0)
    };
    let cpu_unit_percent = int_field("cpuUnitPercent")?;
    let memory_unit_mb = int_field("memoryUnitMb")?;
    let disk_unit_mb = int_field("diskUnitMb")?;
    let min_cpu = int_field("minCpu")?;
    let min_memory_mb = int_field("minMemoryMb")?;
    let min_disk_mb = int_field("minDiskMb")?;

    let dec_field = |key: &str| -> Option<Decimal> {
        let raw = snapshot.get(key)?;
        let s = raw.as_str().map(|s| s.to_string()).or_else(|| match raw {
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })?;
        dec_from_fixed8(&s)
    };
    let cpu_price = dec_field("cpuPricePerUnit")?;
    let memory_price = dec_field("memoryPricePerUnit")?;
    let disk_price = dec_field("diskPricePerUnit")?;
    let reserve_quantum = dec_field("reserveQuantum")?;
    let all_finite_nonneg = [cpu_price, memory_price, disk_price].iter().all(|d| *d >= Decimal::ZERO)
        && reserve_quantum >= Decimal::ZERO;
    if !all_finite_nonneg || reserve_quantum <= Decimal::ZERO {
        return None;
    }

    Some(HourlyPricing {
        cpu_unit_percent,
        memory_unit_mb,
        disk_unit_mb,
        min_cpu,
        min_memory_mb,
        min_disk_mb,
        cpu_price_per_unit: cpu_price,
        memory_price_per_unit: memory_price,
        disk_price_per_unit: disk_price,
        reserve_quantum,
    })
}

fn assert_resource(value: i64, min: i64, step: i64, label: &str) -> Result<(), String> {
    if value < min {
        return Err(format!("{label} must be at least {min}"));
    }
    if step <= 0 || (value - min) % step != 0 {
        return Err(format!("{label} must increase in steps of {step} from {min}"));
    }
    Ok(())
}

pub fn validate_hourly_resources(
    resources: HourlyResources,
    pricing: &HourlyPricing,
) -> Result<(), String> {
    assert_resource(resources.cpu, pricing.min_cpu, pricing.cpu_unit_percent, "CPU")?;
    assert_resource(resources.memory, pricing.min_memory_mb, pricing.memory_unit_mb, "Memory")?;
    assert_resource(resources.disk, pricing.min_disk_mb, pricing.disk_unit_mb, "Disk")?;
    if resources.cpu > 10_000 {
        return Err("CPU is too large".into());
    }
    if resources.memory > 524_288 {
        return Err("Memory is too large".into());
    }
    if resources.disk > 104_857_600 {
        return Err("Disk is too large".into());
    }
    Ok(())
}

pub fn calculate_hourly_breakdown(
    resources: HourlyResources,
    pricing: &HourlyPricing,
) -> Result<HourlyBreakdown, String> {
    validate_hourly_resources(resources, pricing)?;

    let cpu_units_dec = Decimal::from(resources.cpu) / Decimal::from(pricing.cpu_unit_percent);
    let memory_units_dec = Decimal::from(resources.memory) / Decimal::from(pricing.memory_unit_mb);
    let disk_units_dec = Decimal::from(resources.disk) / Decimal::from(pricing.disk_unit_mb);
    let cpu_amount = cpu_units_dec * pricing.cpu_price_per_unit;
    let memory_amount = memory_units_dec * pricing.memory_price_per_unit;
    let disk_amount = disk_units_dec * pricing.disk_price_per_unit;
    Ok(HourlyBreakdown {
        cpu_units: cpu_units_dec.to_f64().unwrap_or(0.0),
        memory_units: memory_units_dec.to_f64().unwrap_or(0.0),
        disk_units: disk_units_dec.to_f64().unwrap_or(0.0),
        cpu_amount,
        memory_amount,
        disk_amount,
        hourly_price: cpu_amount + memory_amount + disk_amount,
    })
}

impl HourlyPricing {
    /// routes serializePricing — plan prices carry no id/version here.
    pub fn to_json(&self) -> Value {
        json!({
            "id": null,
            "version": null,
            "enabled": true,
            "cpuUnitPercent": self.cpu_unit_percent,
            "memoryUnitMb": self.memory_unit_mb,
            "diskUnitMb": self.disk_unit_mb,
            "minCpu": self.min_cpu,
            "minMemoryMb": self.min_memory_mb,
            "minDiskMb": self.min_disk_mb,
            "cpuPricePerUnit": serialize_hourly_decimal(self.cpu_price_per_unit),
            "memoryPricePerUnit": serialize_hourly_decimal(self.memory_price_per_unit),
            "diskPricePerUnit": serialize_hourly_decimal(self.disk_price_per_unit),
            "reserveQuantum": serialize_hourly_decimal(self.reserve_quantum),
            "trafficUnitPrice": "0",
            "trafficIncludedBytes": "0",
            "effectiveAt": null,
        })
    }
}

pub fn serialize_hourly_decimal(value: Decimal) -> String {
    value.round_dp(8).to_string()
}

pub fn serialize_hourly_decimal_opt(value: Option<Decimal>) -> String {
    serialize_hourly_decimal(value.unwrap_or_default())
}

pub fn breakdown_json(b: &HourlyBreakdown) -> Value {
    json!({
        "cpuUnits": b.cpu_units,
        "memoryUnits": b.memory_units,
        "diskUnits": b.disk_units,
        "cpuAmount": serialize_hourly_decimal(b.cpu_amount),
        "memoryAmount": serialize_hourly_decimal(b.memory_amount),
        "diskAmount": serialize_hourly_decimal(b.disk_amount),
        "hourlyPrice": serialize_hourly_decimal(b.hourly_price),
    })
}

#[allow(unused)]
fn _unused(_: &Map<String, Value>) {}
