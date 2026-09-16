mod auth_data;
pub mod authentication;
pub mod registration;
mod shared;

use coset::CoseKey;
use serde::Serialize;
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Credential {
    pub credential_id: Vec<u8>,
    pub public_key: CoseKey,
    pub sign_count: u32,
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_state: bool,
    pub backup_eligible: bool,
}

#[derive(Debug)]
pub struct Authentication {
    pub credential_id: Vec<u8>,
    pub sign_count: u32,
    pub user_verified: bool,
}

#[serde_as]
#[derive(Debug, Serialize)]
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
