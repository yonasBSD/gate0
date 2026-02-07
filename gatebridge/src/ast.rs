//! Policy AST types
//!
//! These types represent the parsed YAML policy structure.
//! Kept deliberately simple - this is data, not behavior.

use serde::Deserialize;

/// Root of a policy file.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    #[serde(default = "default_version")]
    pub policy_schema_version: u32,
    pub default: DefaultPolicy,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

fn default_version() -> u32 { 1 }

/// Fallback when no policy matches.
#[derive(Debug, Clone, Deserialize)]
pub struct DefaultPolicy {
    pub principals: Vec<String>,
    pub max_duration: String,
}

/// A single policy entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub match_block: MatchBlock,
    pub principals: Vec<String>,
    pub max_duration: String,
    #[serde(default)]
    pub trust_budget: Option<TrustBudget>,
}

// serde expects "match" but that's a keyword, so we rename it
impl Policy {
    pub fn match_conditions(&self) -> &MatchBlock {
        &self.match_block
    }
}

/// Match conditions for a policy.
/// First three are OR triggers, last three are AND filters.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchBlock {
    // OR triggers - at least one must match
    #[serde(default)]
    pub oidc_groups: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub local_usernames: Vec<String>,

    // AND filters - all specified must match
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub hours: Vec<String>,
    #[serde(default)]
    pub is_business_hours: Option<bool>,
    #[serde(default)]
    pub webauthn_ids: Vec<String>,
}

/// Metadata for trust budgeting (accounting)
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
pub struct TrustBudget {
    pub budget_id: String,
    pub cost: i32,
    pub initial_balance: i32,
    pub reset_interval_hours: Option<i32>,
}

impl MatchBlock {
    /// True if any OR trigger is specified.
    pub fn has_triggers(&self) -> bool {
        !self.oidc_groups.is_empty()
            || !self.emails.is_empty()
            || !self.local_usernames.is_empty()
    }

    /// True if any AND filter is specified.
    pub fn has_filters(&self) -> bool {
        !self.source_ip.is_empty()
            || !self.hours.is_empty()
            || self.is_business_hours.is_some()
            || !self.webauthn_ids.is_empty()
    }
}

/// A request to evaluate against the policy.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EvalRequest {
    // Identity
    pub oidc_groups: Vec<String>,
    pub email: Option<String>,
    pub local_username: Option<String>,

    // Context
    pub source_ip: Option<String>,
    pub is_business_hours: bool,
    pub hour_utc: u8,
    pub weekday_utc: String, // Expect lowercase "monday", etc.
    pub webauthn_id: Option<String>,
}

impl EvalRequest {
    /// Canonicalize the request (e.g., lowercase identity fields).
    /// Bridge responsibility: ensure input is in "Gold Standard" form.
    pub fn normalize(&mut self) {
        if let Some(e) = self.email.as_mut() {
            *e = e.to_lowercase();
        }
        if let Some(u) = self.local_username.as_mut() {
            *u = u.to_lowercase();
        }
        for g in self.oidc_groups.iter_mut() {
            *g = g.to_lowercase();
        }
        self.weekday_utc = self.weekday_utc.to_lowercase();
    }
}

impl Default for EvalRequest {
    fn default() -> Self {
        EvalRequest {
            oidc_groups: vec![],
            email: None,
            local_username: None,
            source_ip: None,
            is_business_hours: false,
            hour_utc: 0,
            weekday_utc: "monday".to_string(),
            webauthn_id: None,
        }
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalResult {
    pub matched: bool,
    pub policy_name: Option<String>,
    pub policy_index: Option<usize>,
    pub principals: Vec<String>,
    pub max_duration: String,
    pub trust_budget: Option<TrustBudget>,
}

impl EvalResult {
    pub fn default_policy(default: &DefaultPolicy) -> Self {
        EvalResult {
            matched: false,
            policy_name: None,
            policy_index: None,
            principals: default.principals.clone(),
            max_duration: default.max_duration.clone(),
            trust_budget: None,
        }
    }

    pub fn from_policy(policy: &Policy, index: usize) -> Self {
        EvalResult {
            matched: true,
            policy_name: Some(policy.name.clone()),
            policy_index: Some(index),
            principals: policy.principals.clone(),
            max_duration: policy.max_duration.clone(),
            trust_budget: policy.trust_budget.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Idempotence Test: normalize(normalize(x)) == normalize(x)
    /// Ensures canonicalization is stable and doesn't drift.
    #[test]
    fn test_normalize_idempotent() {
        let mut request = EvalRequest {
            oidc_groups: vec!["ADMINS".to_string(), "Security-Team".to_string()],
            email: Some("Alice@EXAMPLE.COM".to_string()),
            local_username: Some("AliceUser".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            is_business_hours: true,
            hour_utc: 14,
            weekday_utc: "MONDAY".to_string(),
            webauthn_id: Some("yubi-123".to_string()),
        };

        // First normalization
        request.normalize();
        let after_first = request.clone();

        // Second normalization
        request.normalize();
        let after_second = request.clone();

        // Should be identical
        assert_eq!(after_first.email, after_second.email);
        assert_eq!(after_first.local_username, after_second.local_username);
        assert_eq!(after_first.oidc_groups, after_second.oidc_groups);
        assert_eq!(after_first.weekday_utc, after_second.weekday_utc);
        
        // Verify lowercase
        assert_eq!(after_second.email, Some("alice@example.com".to_string()));
        assert_eq!(after_second.weekday_utc, "monday");
    }

    /// Bridge Context Contract Test: Verify serialization is stable and deterministic.
    #[test]
    fn test_context_contract_stability() {
        let mut request = EvalRequest {
            oidc_groups: vec!["infrastructure".to_string()],
            email: Some("alice@admin.example.com".to_string()),
            local_username: None,
            source_ip: Some("10.1.2.3".to_string()),
            is_business_hours: true,
            hour_utc: 14,
            weekday_utc: "monday".to_string(),
            webauthn_id: None,
        };
        request.normalize();

        // Serialize and verify determinism
        let json1 = serde_json::to_string(&request).unwrap();
        let json2 = serde_json::to_string(&request).unwrap();
        assert_eq!(json1, json2, "Serialization must be deterministic");

        // Verify round-trip
        let deserialized: EvalRequest = serde_json::from_str(&json1).unwrap();
        let json3 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json1, json3, "Round-trip serialization must be stable");
    }
}
