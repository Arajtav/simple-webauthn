mod auth_data;
pub mod authentication;
pub mod registration;
mod shared;

use coset::{CborSerializable, CoseKey};
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Credential {
    id: Vec<u8>,
    #[serde(
        serialize_with = "serialize_cose_key",
        deserialize_with = "deserialize_cose_key"
    )]
    public_key: CoseKey,
    sign_count: u32,
    user_present: bool,
    user_verified: bool,
    backup_state: bool,
    backup_eligible: bool,
}

impl Credential {
    #[must_use]
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct Base64UrlBytes(#[serde_as(as = "Base64<UrlSafe, Unpadded>")] Vec<u8>);

fn serialize_cose_key<S>(key: &CoseKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = key.clone().to_vec().map_err(serde::ser::Error::custom)?;

    Base64UrlBytes(bytes).serialize(serializer)
}

fn deserialize_cose_key<'de, D>(deserializer: D) -> Result<CoseKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Base64UrlBytes(bytes) = Base64UrlBytes::deserialize(deserializer)?;

    CoseKey::from_slice(&bytes).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authentication {
    pub credential_id: Vec<u8>,
    pub sign_count: u32,
    pub user_verified: bool,
}

#[serde_as]
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum Requirement {
    Required,
    Preferred,
    Discouraged,
}

pub use authentication::{start_authentication, verify_authentication};
pub use registration::{start_registration, verify_registration};
