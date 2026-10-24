//! Instance security-audit engine.
//! Port of server/src/lib/instance-audit.ts — builtin rules, exec output
//! parsers, and the finding analyzer. Pure functions; the DB layer lives in
//! routes/hosts.rs.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};

// ==================== types ====================

pub type AuditSeverity = &'static str; // info | low | medium | high
pub type AuditFindingTarget = &'static str; // process | network | startup | capability
pub type AuditRuleTarget = &'static str; // process | network | startup
pub type AuditRuleMatchType = &'static str; // contains | regex | exact
pub type AuditRuleSource = &'static str; // builtin | custom

#[derive(Debug, Clone)]
pub struct AuditProcess {
    pub pid: i64,
    pub ppid: Option<f64>,
    pub user: String,
    pub stat: String,
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub elapsed: String,
    pub command: String,
    pub args: String,
    pub raw: String,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuditConnection {
    pub protocol: String,
    pub state: String,
    pub local: String,
    pub peer: String,
    pub process: Option<String>,
    pub pid: Option<i64>,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct AuditStartupItem {
    pub source: String,
    pub command: String,
    pub raw: String,
    pub findings: Vec<String>,
}

/// Rule definition used by the analyzer. Builtin rules are static; custom
/// rules and overrides are loaded from the DB into this shape.
#[derive(Debug, Clone)]
pub struct AuditRuleDefinition {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub name: String,
    pub description: Option<String>,
    pub target_types: Vec<String>,
    pub match_type: String,
    pub pattern_text: String,
    pub case_sensitive: bool,
    pub source: &'static str,
    pub enabled: bool,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditIgnoreDefinition {
    pub rule_id: Option<String>,
    pub target_type: Option<String>,
    pub match_text: Option<String>,
    pub reason: Option<String>,
    /// Millis since epoch; None = no expiry.
    pub expires_at: Option<i64>,
}

// ==================== builtin rules ====================

/// BUILTIN_AUDIT_RULES from instance-audit.ts, in order.
pub fn builtin_audit_rules() -> Vec<AuditRuleDefinition> {
    vec![
        AuditRuleDefinition {
            id: "packet-tool-hping".into(),
            severity: "high".into(),
            category: "network-abuse".into(),
            name: "疑似发包工具进程".into(),
            description: Some("匹配常见的发包、构造数据包或压测类工具。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(hping[3]?|nping|mz|mausezahn|mzbench|pktgen|packit|nemesis|tcpreplay|scapy|flood|synflood|udpflood|icmpflood|httpflood|slowloris|goldeneye|hulk|xerxes)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("请先确认进程归属、流量用途和客户业务背景，再决定是否手动处置。".into()),
        },
        AuditRuleDefinition {
            id: "mass-scan-tool".into(),
            severity: "high".into(),
            category: "network-abuse".into(),
            name: "疑似大规模扫描工具".into(),
            description: Some("匹配常见的公网大范围扫描或高频扫描工具。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(masscan|zmap|zdns|zgrab2?|naabu|rustscan|httpx|nuclei|fscan|kscan|gogo|goscan|scanrs|nmap)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("请核实扫描是否经过授权，并结合网络连接、工单或客户说明判断。".into()),
        },
        AuditRuleDefinition {
            id: "flood-tool-name".into(),
            severity: "high".into(),
            category: "network-abuse".into(),
            name: "疑似 Flood/DDoS 程序".into(),
            description: Some("匹配常见 Flood、DDoS 工具名称或命令名称。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(syn[-_]?flood|udp[-_]?flood|http[-_]?flood|slowloris|goldeneye|hulk|xerxes|torshammer|ufonet|mhddos|ddosim|layer[47]|flooder|cc[-_]?attack|stress|hammer|python.*(ddos|flood|attack|hammer)|node.*(ddos|flood|attack))\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("建议按高风险处理。手动停止前请先保留进程参数和连接证据。".into()),
        },
        AuditRuleDefinition {
            id: "proxy-panel".into(),
            severity: "medium".into(),
            category: "proxy-panel".into(),
            name: "疑似代理面板程序".into(),
            description: Some("匹配常见代理面板或相关管理面板名称。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(3x-ui|x-ui|v2-ui|s-ui|h-ui|marzban|v2board|sspanel|xboard|trojan-panel|hiddify|nebula|alpine|sub-web|subconverter|bt-panel|aapanel|aa-panel)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("请确认当前节点规则是否允许此类应用，并结合客户业务说明判断。".into()),
        },
        AuditRuleDefinition {
            id: "proxy-core".into(),
            severity: "medium".into(),
            category: "proxy-panel".into(),
            name: "疑似代理核心进程".into(),
            description: Some("匹配常见代理核心、转发核心或隧道类进程名称。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(xray|v2ray|sing-?box|trojan(-go|rs)?|hysteria2?|naive|brook|gost|ss-server|ss-rust|shadowsocks(-rust)?|tuic|juicity|clash(-meta)?|mihomo|reality|xtls|vless|vmess|frp[cs]?|nps|npc|chisel|ligolo(-ng)?|rathole|bore)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("处置前请核对客户用途、节点政策和实际流量，避免误伤正常服务。".into()),
        },
        AuditRuleDefinition {
            id: "miner".into(),
            severity: "high".into(),
            category: "resource-abuse".into(),
            name: "疑似挖矿进程".into(),
            description: Some("匹配常见加密货币挖矿进程名称。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(xmrig|xmrig-proxy|xmr-stak|xmrigcc|cpuminer|minerd|ethminer|lolminer|nbminer|teamredminer|t-rex|gminer|bzminer|srbminer|wildrig|rigel|miniZ|SRBMiner|moneroocean)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("请结合 CPU 占用、运行时间和服务条款人工确认，违规后再执行处置。".into()),
        },
        AuditRuleDefinition {
            id: "bruteforce".into(),
            severity: "medium".into(),
            category: "credential-attack".into(),
            name: "疑似爆破/撞库工具".into(),
            description: Some("匹配常见密码爆破、登录尝试或凭据攻击工具。".into()),
            target_types: vec!["process".into(), "startup".into()],
            match_type: "regex".into(),
            pattern_text: r"\b(hydra|thc-hydra|medusa|ncrack|patator|crowbar|brutespray|ffuf|gobuster|dirsearch|dirb|sshpass|brute)\b".into(),
            case_sensitive: false,
            source: "builtin",
            enabled: true,
            recommendation: Some("请检查外连目标、登录尝试记录和客户说明，再决定是否手动处理。".into()),
        },
    ]
}

pub fn find_builtin_audit_rule(rule_id: &str) -> Option<AuditRuleDefinition> {
    builtin_audit_rules()
        .into_iter()
        .find(|rule| rule.id == rule_id)
}

// ==================== parsers ====================

fn normalize_command_text(value: &str) -> String {
    let mut out = String::new();
    let mut last_ws = false;
    for c in value.trim().chars() {
        if c.is_whitespace() {
            if !last_ws {
                out.push(' ');
            }
            last_ws = true;
        } else {
            out.push(c);
            last_ws = false;
        }
    }
    out.trim().to_string()
}

fn parse_number(value: &str) -> Option<f64> {
    value.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn js_int(v: f64) -> Option<i64> {
    if v.is_finite() && v.fract() == 0.0 && v.abs() <= 9.007_199_254_740_991e15 {
        Some(v as i64)
    } else {
        None
    }
}

/// Mirrors parseProcesses (ps output rows).
pub fn parse_processes(output: &str, limit: usize) -> Vec<AuditProcess> {
    static ROW: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$")
            .expect("valid regex")
    });
    let mut rows = Vec::new();
    for raw_line in output.split(['\r', '\n']) {
        let raw = raw_line.trim();
        if raw.is_empty() {
            continue;
        }
        let Some(caps) = ROW.captures(raw) else {
            continue;
        };
        let pid_f: f64 = match caps[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(pid) = js_int(pid_f) else {
            continue;
        };
        let command = caps.get(8).map(|m| m.as_str()).unwrap_or("");
        let args = caps
            .get(9)
            .map(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(command);
        rows.push(AuditProcess {
            pid,
            ppid: parse_number(&caps[2]),
            user: caps[3].to_string(),
            stat: caps[4].to_string(),
            cpu_percent: parse_number(&caps[5]),
            memory_percent: parse_number(&caps[6]),
            elapsed: caps[7].to_string(),
            command: command.to_string(),
            args: normalize_command_text(args),
            raw: raw.to_string(),
            findings: Vec::new(),
        });
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn parse_pid_from_process_column(value: &str) -> Option<i64> {
    static PID: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bpid=(\d+)").expect("valid regex"));
    let caps = PID.captures(value)?;
    caps[1].parse::<i64>().ok()
}

/// Mirrors parseConnections (ss/netstat rows).
pub fn parse_connections(output: &str, limit: usize) -> Vec<AuditConnection> {
    let mut rows = Vec::new();
    for raw_line in output.split(['\r', '\n']) {
        let raw = raw_line.trim();
        if raw.is_empty() {
            continue;
        }
        let fields: Vec<&str> = raw.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let process_text: Option<String> = if fields.len() > 6 {
            Some(fields[6..].join(" "))
        } else {
            None
        };
        rows.push(AuditConnection {
            protocol: fields.first().copied().unwrap_or("").to_string(),
            state: fields.get(1).copied().unwrap_or("").to_string(),
            local: fields.get(4).copied().unwrap_or("").to_string(),
            peer: fields.get(5).copied().unwrap_or("").to_string(),
            pid: process_text
            .as_deref()
            .and_then(parse_pid_from_process_column),
            process: process_text,
            raw: raw.to_string(),
        });
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

/// Mirrors parseStartupItems ([section] headers switch the source).
pub fn parse_startup_items(output: &str, limit: usize) -> Vec<AuditStartupItem> {
    static SECTION: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[(.+)\]$").expect("valid regex"));
    let mut rows = Vec::new();
    let mut source = "startup".to_string();
    for raw_line in output.split(['\r', '\n']) {
        let raw = raw_line.trim();
        if raw.is_empty() {
            continue;
        }
        if let Some(caps) = SECTION.captures(raw) {
            source = caps[1].to_string();
            continue;
        }
        rows.push(AuditStartupItem {
            source: source.clone(),
            command: normalize_command_text(raw),
            raw: raw.to_string(),
            findings: Vec::new(),
        });
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

// ==================== analyzer ====================

fn severity_rank(severity: &str) -> i32 {
    match severity {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        _ => 3,
    }
}

fn find_match(rule: &AuditRuleDefinition, text: &str) -> Option<String> {
    if !rule.enabled {
        return None;
    }
    let pattern_text = rule.pattern_text.trim();
    if pattern_text.is_empty() {
        return None;
    }

    if rule.match_type == "regex" {
        let flags = if rule.case_sensitive { "" } else { "i" };
        let regex = Regex::new(&format!("(?{flags}){pattern_text}")).ok()?;
        let caps = regex.captures(text)?;
        return caps
            .get(0)
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty());
    }

    let haystack = if rule.case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };
    let needle = if rule.case_sensitive {
        pattern_text.to_string()
    } else {
        pattern_text.to_lowercase()
    };
    if rule.match_type == "exact" {
        return if haystack.trim() == needle.trim() {
            Some(pattern_text.to_string())
        } else {
            None
        };
    }
    if haystack.contains(&needle) {
        Some(pattern_text.to_string())
    } else {
        None
    }
}

fn is_ignore_active(ignore: &AuditIgnoreDefinition, now_ms: i64) -> bool {
    match ignore.expires_at {
        None => true,
        Some(exp) => exp > now_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_rule_finding(
    id: String,
    rule: &AuditRuleDefinition,
    target_type: &str,
    pid: Option<i64>,
    subject: &str,
    matched_text: &str,
    evidence: &str,
) -> Value {
    let localized = if target_type == "startup" {
        format!("启动项 {subject}")
    } else if target_type == "network" {
        format!("网络连接 {subject}")
    } else {
        subject.to_string()
    };
    json!({
        "id": id,
        "severity": rule.severity,
        "category": rule.category,
        "title": rule.name,
        "detail": format!("{localized} 命中审查规则 {}。", rule.id),
        "targetType": target_type,
        "ruleId": rule.id,
        "ruleName": rule.name,
        "ruleSource": rule.source,
        "matchedText": matched_text,
        "recommendation": rule.recommendation,
        "pid": pid,
        "evidence": evidence.chars().take(800).collect::<String>(),
    })
}

fn apply_ignore(mut finding: Value, ignores: &[AuditIgnoreDefinition], now_ms: i64) -> Value {
    let rule_id = finding.get("ruleId").and_then(Value::as_str).map(String::from);
    let target_type = finding
        .get("targetType")
        .and_then(Value::as_str)
        .map(String::from);
    let title = finding
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let detail = finding
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let evidence = finding
        .get("evidence")
        .and_then(Value::as_str)
        .unwrap_or_default();

    for ignore in ignores {
        if !is_ignore_active(ignore, now_ms) {
            continue;
        }
        if let Some(rid) = &ignore.rule_id {
            if Some(rid.as_str()) != rule_id.as_deref() {
                continue;
            }
        }
        if let Some(tt) = &ignore.target_type {
            if Some(tt.as_str()) != target_type.as_deref() {
                continue;
            }
        }
        if let Some(needle) = &ignore.match_text {
            let text = format!("{title} {detail} {evidence}").to_lowercase();
            if !text.contains(&needle.to_lowercase()) {
                continue;
            }
        }
        if let Some(obj) = finding.as_object_mut() {
            obj.insert("ignored".into(), json!(true));
            obj.insert("ignoreReason".into(), json!(ignore.reason));
        }
        return finding;
    }
    finding
}

/// Mirrors analyzeAuditData. Returns `{ findings, summary }` in the wire shape.
pub fn analyze_audit_data(
    processes: &mut [AuditProcess],
    connections: &[AuditConnection],
    startup_items: &mut [AuditStartupItem],
    rules: &[AuditRuleDefinition],
    ignores: &[AuditIgnoreDefinition],
) -> (Vec<Value>, Value) {
    let mut findings: Vec<Value> = Vec::new();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let active_rules: Vec<&AuditRuleDefinition> = rules.iter().filter(|r| r.enabled).collect();

    for (index, process) in processes.iter_mut().enumerate() {
        let text = format!("{} {}", process.command, process.args);
        for rule in active_rules
            .iter()
            .filter(|r| r.target_types.iter().any(|t| t == "process"))
        {
            let Some(matched_text) = find_match(rule, &text) else {
                continue;
            };
            process.findings.push(rule.name.clone());
            findings.push(build_rule_finding(
                format!("process-{index}-{}", rule.id),
                rule,
                "process",
                Some(process.pid),
                &format!("PID {} ({})", process.pid, process.command),
                &matched_text,
                &process.raw,
            ));
        }
    }

    for (index, item) in startup_items.iter_mut().enumerate() {
        for rule in active_rules
            .iter()
            .filter(|r| r.target_types.iter().any(|t| t == "startup"))
        {
            let Some(matched_text) = find_match(rule, &item.command) else {
                continue;
            };
            item.findings.push(rule.name.clone());
            findings.push(build_rule_finding(
                format!("startup-{index}-{}", rule.id),
                rule,
                "startup",
                None,
                &format!("来源 {}", item.source),
                &matched_text,
                &item.raw,
            ));
        }
    }

    for (index, connection) in connections.iter().enumerate() {
        for rule in active_rules
            .iter()
            .filter(|r| r.target_types.iter().any(|t| t == "network"))
        {
            let Some(matched_text) = find_match(rule, &connection.raw) else {
                continue;
            };
            findings.push(build_rule_finding(
                format!("network-{index}-{}", rule.id),
                rule,
                "network",
                connection.pid,
                &format!(
                    "{} {} -> {}",
                    connection.protocol, connection.local, connection.peer
                ),
                &matched_text,
                &connection.raw,
            ));
        }
    }

    let udp_connections = connections
        .iter()
        .filter(|row| row.protocol.to_lowercase().starts_with("udp"))
        .count();
    if udp_connections >= 100 {
        let evidence = connections
            .iter()
            .filter(|row| row.protocol.to_lowercase().starts_with("udp"))
            .take(5)
            .map(|row| row.raw.clone())
            .collect::<Vec<_>>()
            .join("\n");
        findings.push(json!({
            "id": "network-high-udp-connection-count",
            "severity": "medium",
            "category": "network-anomaly",
            "title": "UDP 连接数量偏高",
            "detail": format!("本次扫描从 ss/netstat 返回 {udp_connections} 条 UDP 连接记录，请结合业务用途判断是否异常。"),
            "targetType": "network",
            "evidence": evidence,
        }));
    }

    let mut high_cpu: Vec<&AuditProcess> = processes
        .iter()
        .filter(|p| p.cpu_percent.unwrap_or(0.0) >= 80.0)
        .collect();
    high_cpu.truncate(5);
    for process in high_cpu {
        findings.push(json!({
            "id": format!("process-{}-high-cpu", process.pid),
            "severity": "low",
            "category": "resource-anomaly",
            "title": "CPU 占用偏高的进程",
            "detail": format!("PID {} 当前 CPU 占用为 {}%。", process.pid, process.cpu_percent.unwrap_or(0.0)),
            "targetType": "process",
            "pid": process.pid,
            "evidence": process.raw.chars().take(500).collect::<String>(),
        }));
    }

    let listening_count = connections
        .iter()
        .filter(|row| row.state.to_uppercase() == "LISTEN")
        .count();

    let mut annotated: Vec<Value> = findings
        .into_iter()
        .map(|f| apply_ignore(f, ignores, now_ms))
        .collect();

    // TS maxSeverity(activeFindings): empty -> 'info'; otherwise start at
    // 'low' and take the max active severity rank.
    let active_severities: Vec<&str> = annotated
        .iter()
        .filter(|f| f.get("ignored").and_then(Value::as_bool) != Some(true))
        .map(|f| f.get("severity").and_then(Value::as_str).unwrap_or("info"))
        .collect();
    let risk_level: &str = if active_severities.is_empty() {
        "info"
    } else {
        let max_rank = active_severities
            .iter()
            .map(|s| severity_rank(s))
            .fold(1i32, |acc, r| acc.max(r));
        match max_rank {
            3 => "high",
            2 => "medium",
            _ => "low",
        }
    };

    annotated.sort_by(|a, b| {
        let a_ignored = a.get("ignored").and_then(Value::as_bool) == Some(true);
        let b_ignored = b.get("ignored").and_then(Value::as_bool) == Some(true);
        // Number(a.ignored) - Number(b.ignored): false(0) sorts first.
        a_ignored.cmp(&b_ignored).then_with(|| {
            let sev = |v: &Value| {
                severity_rank(v.get("severity").and_then(Value::as_str).unwrap_or("info"))
            };
            sev(b).cmp(&sev(a))
        })
    });

    let summary = json!({
        "riskLevel": risk_level,
        "processCount": processes.len(),
        "connectionCount": connections.len(),
        "listeningCount": listening_count,
        "startupItemCount": startup_items.len(),
        "findingCount": annotated.iter().filter(|f| f.get("ignored").and_then(Value::as_bool) != Some(true)).count(),
    });

    (annotated, summary)
}

// ==================== exec command builders ====================

pub fn build_process_audit_command() -> String {
    "ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --no-headers 2>/dev/null | head -n 300 || true"
        .to_string()
}

pub fn build_connection_audit_command() -> String {
    "(ss -H -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true) | head -n 300".to_string()
}

pub fn build_startup_audit_command() -> String {
    [
        "printf \"[systemd]\\n\"",
        "(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -n 80 || true)",
        "printf \"[cron]\\n\"",
        "(crontab -l 2>/dev/null || true)",
        "printf \"[rc-local]\\n\"",
        "(test -f /etc/rc.local && sed -n \"1,120p\" /etc/rc.local || true)",
        "printf \"[supervisor]\\n\"",
        "(command -v supervisorctl >/dev/null 2>&1 && supervisorctl status 2>/dev/null || true)",
        "printf \"[pm2]\\n\"",
        "(command -v pm2 >/dev/null 2>&1 && pm2 list --no-color 2>/dev/null || true)",
    ]
    .join("; ")
}

/// Serialize a process row for the scan response.
pub fn process_json(p: &AuditProcess) -> Value {
    json!({
        "pid": p.pid,
        "ppid": p.ppid,
        "user": p.user,
        "stat": p.stat,
        "cpuPercent": p.cpu_percent,
        "memoryPercent": p.memory_percent,
        "elapsed": p.elapsed,
        "command": p.command,
        "args": p.args,
        "raw": p.raw,
        "findings": p.findings,
    })
}

pub fn connection_json(c: &AuditConnection) -> Value {
    json!({
        "protocol": c.protocol,
        "state": c.state,
        "local": c.local,
        "peer": c.peer,
        "process": c.process,
        "pid": c.pid,
        "raw": c.raw,
    })
}

pub fn startup_item_json(s: &AuditStartupItem) -> Value {
    json!({
        "source": s.source,
        "command": s.command,
        "raw": s.raw,
        "findings": s.findings,
    })
}

/// Truncate helper used when persisting findings (slice(0, 80) in TS).
pub fn truncate_findings(findings: Vec<Value>, max: usize) -> Vec<Value> {
    findings.into_iter().take(max).collect()
}

/// Mirror of the routes' `normalizeProcessText` helper.
pub fn normalize_process_text(value: &str) -> String {
    normalize_command_text(value)
}

/// Helper to build an empty findings object map when storing scans.
pub fn empty_findings() -> Map<String, Value> {
    Map::new()
}
