use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use sha2::Digest;

use crate::Requirement;

// TODO
#[derive(Debug, Serialize)]
pub struct Hint {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Internal,
    Usb,
    Nfc,
    Ble,
    Hybrid,
    Cable,
}

#[derive(Debug)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: Requirement,
    pub user_verification: Requirement,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response<R> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub raw_id: Vec<u8>,
    #[allow(clippy::struct_field_names)]
    pub response: R,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(default)]
    pub client_extension_results: ExtensionResults,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

impl<R> Response<R> {
    pub fn credential_id(&self) -> &[u8] {
        &self.id
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

// Also not yet
#[derive(Debug, Deserialize, Default)]
pub struct ExtensionResults {}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub challenge: Vec<u8>,
    pub origin: String,
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct CredentialInfo {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Vec<u8>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub transport: Vec<Transport>,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    challenge
}
