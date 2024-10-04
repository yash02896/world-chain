use std::str::FromStr;

use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use chrono::{Datelike, NaiveDate};
use semaphore::packed_proof::PackedProof;
use semaphore::Field;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::tx::Prefix;

pub const TREE_DEPTH: usize = 30;

const LEN: usize = 256;

pub type ProofBytes = [u8; LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(pub semaphore::protocol::Proof);

impl Default for Proof {
    fn default() -> Self {
        let proof = semaphore::protocol::Proof(
            (0u64.into(), 0u64.into()),
            ([0u64.into(), 0u64.into()], [0u64.into(), 0u64.into()]),
            (0u64.into(), 0u64.into()),
        );

        Proof(proof)
    }
}

impl Decodable for Proof {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = ProofBytes::decode(buf)?;
        Ok(Proof(PackedProof(bytes).into()))
    }
}

impl Encodable for Proof {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let PackedProof(bytes) = self.0.into();
        bytes.encode(out)
    }

    fn length(&self) -> usize {
        LEN + 3
    }
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable, PartialEq, Eq, Default)]
pub struct SemaphoreProof {
    pub external_nullifier: String,
    pub external_nullifier_hash: Field,
    pub nullifier_hash: Field,
    pub signal_hash: Field,
    pub root: Field,
    pub proof: Proof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalNullifier {
    pub month: DateMarker,
    pub nonce: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateMarker {
    pub year: i32,
    pub month: u32,
}

impl ExternalNullifier {
    pub fn new(month: DateMarker, nonce: u16) -> Self {
        Self { month, nonce }
    }
}

impl std::fmt::Display for ExternalNullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}", Prefix::V1, self.month, self.nonce)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExternalNullifierParsingError {
    #[error("invalid format - expected a string of format `vv-mmyyyy-xxx...` got {actual}")]
    InvaldFormat { actual: String },

    #[error("error parsing prefix - {0}")]
    InvalidPrefix(strum::ParseError),

    #[error("error parsing month - {0}")]
    InvalidMonth(MonthMarkerParsingError),

    #[error("error parsing nonce - {0}")]
    InvalidNonce(std::num::ParseIntError),

    #[error("leading zeroes in nonce `{0}`")]
    LeadingZeroes(String),
}

impl FromStr for ExternalNullifier {
    type Err = ExternalNullifierParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return Err(ExternalNullifierParsingError::InvaldFormat {
                actual: s.to_string(),
            });
        }

        // no need to check the exact value since there's only one variant
        let Prefix::V1 = parts[0]
            .parse()
            .map_err(ExternalNullifierParsingError::InvalidPrefix)?;

        let month = parts[1]
            .parse()
            .map_err(ExternalNullifierParsingError::InvalidMonth)?;

        let nonce_str = parts[2];
        let nonce_str_trimmed = nonce_str.trim_start_matches('0');

        if nonce_str != "0" && nonce_str != nonce_str_trimmed {
            return Err(ExternalNullifierParsingError::LeadingZeroes(
                nonce_str.to_string(),
            ));
        }

        let nonce = nonce_str
            .parse()
            .map_err(ExternalNullifierParsingError::InvalidNonce)?;

        Ok(ExternalNullifier { month, nonce })
    }
}

impl DateMarker {
    pub fn new(year: i32, month: u32) -> Self {
        Self { year, month }
    }
}

impl<T> From<T> for DateMarker
where
    T: Datelike,
{
    fn from(value: T) -> Self {
        Self {
            year: value.year(),
            month: value.month(),
        }
    }
}

impl From<DateMarker> for NaiveDate {
    fn from(value: DateMarker) -> Self {
        NaiveDate::from_ymd_opt(value.year, value.month, 1).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MonthMarkerParsingError {
    #[error("invalid length - expected 6 characters got {actual}")]
    InvaldLength { actual: usize },
    #[error("error parsing month - {0}")]
    InvalidMonth(std::num::ParseIntError),
    #[error("month out of range - expected 01-12 got {month}")]
    MonthOutOfRange { month: u32 },
    #[error("error parsing year - {0}")]
    InvalidYear(std::num::ParseIntError),
}

impl FromStr for DateMarker {
    type Err = MonthMarkerParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 6 {
            return Err(MonthMarkerParsingError::InvaldLength { actual: s.len() });
        }

        let month = &s[..2];
        let year = &s[2..];

        let month = month
            .parse()
            .map_err(MonthMarkerParsingError::InvalidMonth)?;
        let year = year.parse().map_err(MonthMarkerParsingError::InvalidYear)?;

        if !(1..=12).contains(&month) {
            return Err(MonthMarkerParsingError::MonthOutOfRange { month });
        }

        Ok(DateMarker { year, month })
    }
}

impl std::fmt::Display for DateMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}{:04}", self.month, self.year)
    }
}

#[cfg(test)]
mod test {
    use ethers_core::types::U256;
    use test_case::test_case;

    use super::*;

    #[test]
    fn encode_decode() {
        let proof = Proof(semaphore::protocol::Proof(
            (U256::from(1u64), U256::from(2u64)),
            (
                [U256::from(3u64), U256::from(4u64)],
                [U256::from(5u64), U256::from(6u64)],
            ),
            (U256::from(7u64), U256::from(8u64)),
        ));
        let semaphore_proof = SemaphoreProof {
            external_nullifier: "0-012025-11".to_string(),
            external_nullifier_hash: Field::from(9u64),
            nullifier_hash: Field::from(10u64),
            signal_hash: Field::from(11u64),
            root: Field::from(12u64),
            proof,
        };
        let encoded = alloy_rlp::encode(&semaphore_proof);
        let mut buf = encoded.as_slice();
        let decoded = SemaphoreProof::decode(&mut buf).unwrap();
        assert_eq!(semaphore_proof, decoded);
    }

    #[test_case("v1-012025-11")]
    #[test_case("v1-012025-19")]
    fn parse_external_nulliifer_roundtrip(s: &str) {
        let e: ExternalNullifier = s.parse().unwrap();

        assert_eq!(e.to_string(), s);
    }

    #[test_case("v2-012025-11")]
    #[test_case("v1-012025-011")]
    fn parse_external_nulliifer_invalid(s: &str) {
        s.parse::<ExternalNullifier>().unwrap_err();
    }

    #[test_case("012024")]
    #[test_case("022024")]
    #[test_case("022025")]
    fn parse_month_marker_roundtrip(s: &str) {
        let m: DateMarker = s.parse().unwrap();

        assert_eq!(m.to_string(), s);
    }

    #[test_case("132024" ; "invalid month")]
    #[test_case("12024" ; "too short")]
    #[test_case("003024" ; "zero month")]
    #[test_case("" ; "empty")]
    #[test_case("23012024" ; "too long")]
    fn parse_month_marker_invalid(s: &str) {
        s.parse::<DateMarker>().unwrap_err();
    }
}
