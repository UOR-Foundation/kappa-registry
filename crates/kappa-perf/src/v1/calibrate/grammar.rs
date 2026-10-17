//! OSC identifier: `osc:quantity/operation?condition=value&...@arch.os.runtime`.
//!
//! The identifier is a measurement's primary key. Two identifiers name the
//! same measurement exactly when their canonical forms are byte-identical:
//! operands are sorted and deduplicated, conditions are sorted by key and
//! canonicalized by value, and the scheme is always `osc:`. Construction
//! validates against the registries, so an identifier that exists has a
//! registered quantity, registered operands and applicable conditions.

use std::fmt;
use std::str::FromStr;

use super::condition::{ConditionError, Conditions};
use super::operation::{OperationError, OperationPath};
use super::profile::Profile;
use super::quantity::Quantity;
use super::substrate::Substrate;

/// Identifier grammar version, embedded in every record.
pub const GRAMMAR_VERSION: &str = "1.0.0";

/// A validated, canonical measurement identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OscId {
    quantity: Quantity,
    operation: OperationPath,
    conditions: Conditions,
    substrate: Option<Substrate>,
}

/// Why an identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("identifier must begin with 'osc:'")]
    MissingScheme,
    #[error("missing quantity before '/'")]
    MissingQuantity,
    #[error("unregistered quantity '{0}'")]
    UnregisteredQuantity(String),
    #[error("missing operation after '/'")]
    MissingOperation,
    #[error(transparent)]
    Operation(#[from] OperationError),
    #[error(transparent)]
    Condition(#[from] ConditionError),
    #[error("quantity '{quantity}' requires condition '{key}'")]
    MissingRequiredCondition {
        quantity: Quantity,
        key: &'static str,
    },
    #[error("invalid substrate '{0}'")]
    InvalidSubstrate(String),
}

impl OscId {
    /// Build from parts, enforcing condition applicability and required
    /// conditions.
    pub fn new(
        quantity: Quantity,
        operation: &str,
        conditions: Conditions,
    ) -> Result<Self, ParseError> {
        let operation = OperationPath::parse(operation)?;
        Self::validated(quantity, operation, conditions, None, Profile::L1Conditions)
    }

    /// Shorthand for an unconditioned identifier.
    pub fn simple(quantity: Quantity, operation: &str) -> Result<Self, ParseError> {
        Self::new(quantity, operation, Conditions::new())
    }

    /// Parse at `profile`. L0 checks the quantity and operation registries;
    /// L1 and above also check conditions.
    pub fn parse(raw: &str, profile: Profile) -> Result<Self, ParseError> {
        let rest = raw.strip_prefix("osc:").ok_or(ParseError::MissingScheme)?;
        let (rest, substrate) = match rest.rsplit_once('@') {
            Some((rest, substrate)) => (
                rest,
                Some(
                    Substrate::parse(substrate)
                        .ok_or_else(|| ParseError::InvalidSubstrate(substrate.to_owned()))?,
                ),
            ),
            None => (rest, None),
        };
        let (rest, conditions) = match rest.split_once('?') {
            Some((rest, conditions)) => (rest, Conditions::parse(conditions)?),
            None => (rest, Conditions::new()),
        };
        let (quantity, operation) = rest.split_once('/').ok_or(ParseError::MissingOperation)?;
        if quantity.is_empty() {
            return Err(ParseError::MissingQuantity);
        }
        if operation.is_empty() {
            return Err(ParseError::MissingOperation);
        }
        let quantity = Quantity::from_token(quantity)
            .ok_or_else(|| ParseError::UnregisteredQuantity(quantity.to_owned()))?;
        let operation = OperationPath::parse(operation)?;
        Self::validated(quantity, operation, conditions, substrate, profile)
    }

    fn validated(
        quantity: Quantity,
        operation: OperationPath,
        conditions: Conditions,
        substrate: Option<Substrate>,
        profile: Profile,
    ) -> Result<Self, ParseError> {
        if profile >= Profile::L1Conditions {
            conditions.check_applicable(&operation.domains())?;
            if let Some(key) = quantity
                .required_conditions()
                .iter()
                .find(|key| !conditions.contains_key(key))
            {
                return Err(ParseError::MissingRequiredCondition { quantity, key });
            }
        }
        Ok(Self {
            quantity,
            operation,
            conditions,
            substrate,
        })
    }

    /// Canonical form; the record primary key.
    pub fn canonical(&self) -> String {
        let mut out = format!(
            "osc:{}/{}{}",
            self.quantity, self.operation, self.conditions
        );
        if let Some(substrate) = &self.substrate {
            out.push('@');
            out.push_str(&substrate.to_string());
        }
        out
    }

    /// This identifier bound to `substrate` when it carries none.
    #[must_use]
    pub fn with_substrate(&self, substrate: &Substrate) -> Self {
        let mut id = self.clone();
        if id.substrate.is_none() {
            id.substrate = Some(substrate.clone());
        }
        id
    }

    #[must_use]
    pub fn strip_substrate(&self) -> Self {
        Self {
            substrate: None,
            ..self.clone()
        }
    }

    #[must_use]
    pub fn strip_conditions(&self) -> Self {
        Self {
            conditions: Conditions::new(),
            ..self.clone()
        }
    }

    /// Same quantity and operation, every condition of `other` present, and
    /// `other`'s substrate absent or equal. Reflexive.
    pub fn is_more_specific_than(&self, other: &Self) -> bool {
        self.quantity == other.quantity
            && self.operation == other.operation
            && self.conditions.is_superset_of(&other.conditions)
            && other
                .substrate
                .as_ref()
                .is_none_or(|substrate| self.substrate.as_ref() == Some(substrate))
    }

    pub const fn quantity(&self) -> Quantity {
        self.quantity
    }

    pub const fn operation(&self) -> &OperationPath {
        &self.operation
    }

    pub const fn conditions(&self) -> &Conditions {
        &self.conditions
    }

    pub const fn substrate(&self) -> Option<&Substrate> {
        self.substrate.as_ref()
    }
}

impl fmt::Display for OscId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl FromStr for OscId {
    type Err = ParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw, Profile::L1Conditions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn canonical_simple() -> TestResult {
        let id = OscId::simple(Quantity::Lat, "store.publish")?;
        assert_eq!(id.canonical(), "osc:lat/store.publish");
        assert_eq!(id.to_string(), id.canonical());
        Ok(())
    }

    #[test]
    fn canonical_sorts_and_canonicalizes_conditions() -> TestResult {
        let a: OscId = "osc:lat/store.publish?tags=1000&backend=redb".parse()?;
        let b: OscId = "osc:lat/store.publish?backend=redb&tags=1000".parse()?;
        assert_eq!(a, b);
        assert_eq!(
            a.canonical(),
            "osc:lat/store.publish?backend=redb&tags=1000"
        );
        let c: OscId = "osc:bw/hash.sha256?size=65536".parse()?;
        assert_eq!(c.canonical(), "osc:bw/hash.sha256?size=64k");
        Ok(())
    }

    #[test]
    fn composition_and_substrate_roundtrip() -> TestResult {
        let raw = "osc:lat/store.tag_put+crypto.sign.ed25519?threads=4t@x86_64.linux.std";
        let id: OscId = raw.parse()?;
        assert_eq!(
            id.canonical(),
            "osc:lat/crypto.sign.ed25519+store.tag_put?threads=4t@x86_64.linux.std"
        );
        let reparsed: OscId = id.canonical().parse()?;
        assert_eq!(id, reparsed);
        Ok(())
    }

    type Expectation = fn(&ParseError) -> bool;

    #[test]
    fn rejects_malformed_identifiers() {
        let cases: &[(&str, Expectation)] = &[
            ("lat/store.publish", |e| {
                matches!(e, ParseError::MissingScheme)
            }),
            ("osc:/store.publish", |e| {
                matches!(e, ParseError::MissingQuantity)
            }),
            ("osc:lat/", |e| matches!(e, ParseError::MissingOperation)),
            ("osc:lat", |e| matches!(e, ParseError::MissingOperation)),
            ("osc:xyz/store.publish", |e| {
                matches!(e, ParseError::UnregisteredQuantity(_))
            }),
            ("osc:lat/store.bogus", |e| {
                matches!(e, ParseError::Operation(_))
            }),
            ("osc:lat/store.publish?bogus=1", |e| {
                matches!(e, ParseError::Condition(_))
            }),
            ("osc:lat/hash.sha256?backend=redb", |e| {
                matches!(e, ParseError::Condition(_))
            }),
            ("osc:cost/hash.sha256?size=1m", |e| {
                matches!(e, ParseError::MissingRequiredCondition { .. })
            }),
            ("osc:lat/store.publish@x86_64.linux", |e| {
                matches!(e, ParseError::InvalidSubstrate(_))
            }),
        ];
        for (raw, expected) in cases {
            match raw.parse::<OscId>() {
                Ok(id) => panic!("{raw} parsed as {id}"),
                Err(error) => assert!(expected(&error), "{raw}: unexpected {error:?}"),
            }
        }
    }

    #[test]
    fn l0_skips_condition_applicability_only() -> TestResult {
        let id = OscId::parse("osc:lat/hash.sha256?backend=redb", Profile::L0Core)?;
        assert_eq!(id.conditions().get("backend"), Some("redb"));
        assert!(OscId::parse("osc:lat/hash.bogus", Profile::L0Core).is_err());
        Ok(())
    }

    #[test]
    fn specificity_and_projections() -> TestResult {
        let general: OscId = "osc:lat/store.publish".parse()?;
        let specific: OscId = "osc:lat/store.publish?backend=redb@x86_64.linux.std".parse()?;
        assert!(specific.is_more_specific_than(&general));
        assert!(!general.is_more_specific_than(&specific));
        assert!(specific.is_more_specific_than(&specific));
        assert_eq!(specific.strip_substrate().strip_conditions(), general);
        let other: OscId = "osc:bw/store.publish".parse()?;
        assert!(!other.is_more_specific_than(&general));
        Ok(())
    }

    #[test]
    fn with_substrate_does_not_override() -> TestResult {
        let id: OscId = "osc:lat/store.publish@aarch64.linux.std".parse()?;
        let host = Substrate::parse("x86_64.linux.std").ok_or("substrate")?;
        assert_eq!(id.with_substrate(&host), id);
        let bare = id.strip_substrate().with_substrate(&host);
        assert_eq!(bare.substrate(), Some(&host));
        Ok(())
    }
}
