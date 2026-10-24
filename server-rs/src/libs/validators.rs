//! Input validators, verbatim port of the validation half of
//! server/src/lib/security.ts (validatePassword / containsDangerousChars /
//! removeDangerousChars / validateName / validateIdentifier / validateText).
//!
//! The regexes and the exact error-message strings are wire contracts: the TS
//! server sends `message` back to the client in several routes (e.g. ssh-keys
//! `POST /` sends `{ error: nameValidation.message }` bare).

use once_cell::sync::Lazy;
use regex::Regex;

/// 危险字符正则: 禁止 ' " \ / ? ] [ = + . < > ` ; : | ! @ # $ % ^ & * { } ~
/// 允许: ( ) 空格 , — and anything CJK/alphanumeric.
static DANGEROUS_CHARS_REGEX: Lazy<Regex> = Lazy::new(|| {
    // TS source: /['"\\\/?[\]=+.<>`;\:|!@#$%^&*\{\}~]/
    Regex::new(r#"['"\\/?\[\]=+.<>`;:|!@#$%^&*{}~]"#).expect("valid regex")
});

/// 安全名称正则（只允许字母、数字、连字符、下划线、空格、逗号、圆括号和中文）
static SAFE_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    // TS source: /^[\u4e00-\u9fa5a-zA-Z0-9\-_ ,()]+$/
    Regex::new(r"^[\u{4e00}-\u{9fa5}a-zA-Z0-9\-_ ,()]+$").expect("valid regex")
});

/// 严格名称正则（只允许字母、数字、连字符、下划线，必须以字母或数字开头）
static STRICT_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    // TS source: /^[a-zA-Z0-9][a-zA-Z0-9\-_]*$/
    Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-_]*$").expect("valid regex")
});

/// Result mirror of the TS `InputValidationResult`:
/// `{ valid, message?, sanitized? }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputValidation {
    pub valid: bool,
    pub message: Option<String>,
    pub sanitized: Option<String>,
}

impl InputValidation {
    fn ok(sanitized: String) -> Self {
        Self {
            valid: true,
            message: None,
            sanitized: Some(sanitized),
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            message: Some(message.into()),
            sanitized: None,
        }
    }
}

/// Mirrors containsDangerousChars().
pub fn contains_dangerous_chars(input: &str) -> bool {
    DANGEROUS_CHARS_REGEX.is_match(input)
}

/// Mirrors removeDangerousChars().
pub fn remove_dangerous_chars(input: &str) -> String {
    DANGEROUS_CHARS_REGEX.replace_all(input, "").into_owned()
}

/// Mirrors validateName(name, fieldName, minLength, maxLength):
/// 通用名称输入（允许中文、字母、数字、连字符、下划线、空格）.
pub fn validate_name(
    name: &str,
    field_name: &str,
    min_length: usize,
    max_length: usize,
) -> InputValidation {
    if name.is_empty() {
        return InputValidation::fail(format!("{field_name} cannot be empty"));
    }

    let trimmed = name.trim();

    if trimmed.chars().count() < min_length {
        return InputValidation::fail(format!(
            "{field_name} must be at least {min_length} characters"
        ));
    }

    if trimmed.chars().count() > max_length {
        return InputValidation::fail(format!(
            "{field_name} cannot exceed {max_length} characters"
        ));
    }

    if contains_dangerous_chars(trimmed) {
        return InputValidation::fail(format!("{field_name} contains illegal characters"));
    }

    if !SAFE_NAME_REGEX.is_match(trimmed) {
        return InputValidation::fail(format!(
            "{field_name} can only contain letters, numbers, Chinese, hyphens, underscores, spaces, commas and parentheses"
        ));
    }

    InputValidation::ok(trimmed.to_string())
}

/// Mirrors validateIdentifier(input, fieldName, minLength, maxLength):
/// 技术标识符（只允许字母、数字、连字符、下划线，必须以字母或数字开头）.
pub fn validate_identifier(
    input: &str,
    field_name: &str,
    min_length: usize,
    max_length: usize,
) -> InputValidation {
    if input.is_empty() {
        return InputValidation::fail(format!("{field_name} cannot be empty"));
    }

    let trimmed = input.trim();

    if trimmed.chars().count() < min_length {
        return InputValidation::fail(format!(
            "{field_name} must be at least {min_length} characters"
        ));
    }

    if trimmed.chars().count() > max_length {
        return InputValidation::fail(format!(
            "{field_name} cannot exceed {max_length} characters"
        ));
    }

    if !STRICT_NAME_REGEX.is_match(trimmed) {
        return InputValidation::fail(format!(
            "{field_name} can only contain letters, numbers, hyphens and underscores, and must start with a letter or number"
        ));
    }

    InputValidation::ok(trimmed.to_string())
}

/// Mirrors validateText(text, fieldName, maxLength):
/// 通用文本输入（移除危险字符但允许更多内容）.
pub fn validate_text(text: &str, field_name: &str, max_length: usize) -> InputValidation {
    if text.is_empty() {
        return InputValidation::fail(format!("{field_name} cannot be empty"));
    }

    let sanitized = remove_dangerous_chars(text);

    if sanitized.chars().count() > max_length {
        return InputValidation::fail(format!(
            "{field_name} cannot exceed {max_length} characters"
        ));
    }

    InputValidation::ok(sanitized)
}

/// Result mirror of the TS `PasswordValidationResult` — `message` is sent to
/// the client on PASSWORD_TOO_WEAK errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordValidation {
    pub valid: bool,
    pub message: Option<String>,
}

/// Mirrors validatePassword(password):
/// 至少8字符，且必须包含大写字母、小写字母和数字；上限 128 字符.
pub fn validate_password(password: &str) -> PasswordValidation {
    let mut result = PasswordValidation {
        valid: true,
        message: None,
    };
    let length = password.chars().count();

    if length < 8 {
        result.valid = false;
        result.message = Some("Password must be at least 8 characters".to_string());
        return result;
    }

    if length > 128 {
        result.valid = false;
        result.message = Some("Password cannot exceed 128 characters".to_string());
        return result;
    }

    // 严格密码策略：必须包含大写、小写和数字
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        result.valid = false;
        result.message =
            Some("Password must contain at least one uppercase letter".to_string());
        return result;
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        result.valid = false;
        result.message =
            Some("Password must contain at least one lowercase letter".to_string());
        return result;
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        result.valid = false;
        result.message = Some("Password must contain at least one number".to_string());
        return result;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_chars() {
        assert!(!contains_dangerous_chars("hello world"));
        assert!(!contains_dangerous_chars("节点-01 (主)"));
        assert!(contains_dangerous_chars("a'b"));
        assert!(contains_dangerous_chars("a\"b"));
        assert!(contains_dangerous_chars("a\\b"));
        assert!(contains_dangerous_chars("a/b"));
        assert!(contains_dangerous_chars("a.b"));
        assert!(contains_dangerous_chars("a=b"));
        assert!(contains_dangerous_chars("a@b"));
        assert!(contains_dangerous_chars("a`b"));
        // Allowed punctuation
        assert!(!contains_dangerous_chars("a,b (c)"));
    }

    #[test]
    fn name_validation() {
        assert!(validate_name("", "Name", 1, 50).message.unwrap().contains("cannot be empty"));
        assert!(validate_name("ab", "Name", 3, 50).message.unwrap().contains("at least 3"));
        assert!(validate_name("abc", "Key name", 1, 2).message.unwrap().contains("cannot exceed 2"));
        let ok = validate_name(" 主机 01 ", "Name", 1, 64);
        assert!(ok.valid);
        assert_eq!(ok.sanitized.as_deref(), Some("主机 01"));
        assert!(validate_name("bad.name", "Name", 1, 64).message.unwrap().contains("illegal"));
        // TS checks containsDangerousChars BEFORE SAFE_NAME_REGEX, so '~' yields
        // the illegal-characters message, not the can-only-contain one.
        assert!(validate_name("bad~name", "Name", 1, 64).message.unwrap().contains("illegal"));
    }

    #[test]
    fn identifier_validation() {
        assert!(validate_identifier("user_01", "Username", 2, 64).valid);
        assert!(validate_identifier("-user", "Username", 2, 64)
            .message
            .unwrap()
            .contains("must start with"));
        assert!(validate_identifier("us er", "Username", 2, 64)
            .message
            .unwrap()
            .contains("only contain"));
    }

    #[test]
    fn password_validation() {
        assert!(validate_password("short").message.unwrap().contains("at least 8"));
        assert!(validate_password("alllowercase1").message.unwrap().contains("uppercase"));
        assert!(validate_password("ALLUPPERCASE1").message.unwrap().contains("lowercase"));
        assert!(validate_password("NoDigitsHere").message.unwrap().contains("number"));
        assert!(validate_password("GoodPass1").valid);
    }
}
