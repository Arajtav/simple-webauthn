use serde::Deserialize;
use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub challenge: Vec<u8>,
    pub rp: Rp,
    pub user: User,
    pub timeout: i32,
    pub attestation: Attestation,
    pub hints: Vec<Hint>,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub exclude_credentials: Vec<ExcludeCredential>,
    pub authenticator_selection: AuthenticatorSelection,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Serialize)]
pub struct Rp {
    pub name: String,
    pub id: String,
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

// TODO
#[derive(Debug, Serialize)]
pub enum Attestation {
    None,
}

#[derive(Debug, Serialize)]
pub struct Hint {}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub alg: Algorithm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    PublicKey,
}

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    ES256 = -7,
    EdDSA = -8,
    RS256 = -257,
}

impl Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (*self as i16).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i16::deserialize(deserializer)?;

        match value {
            -7 => Ok(Algorithm::ES256),
            -8 => Ok(Algorithm::EdDSA),
            -257 => Ok(Algorithm::RS256),
            _ => Err(serde::de::Error::custom(format!(
                "unknown algorithm: {value}"
            ))),
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ExcludeCredential {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Vec<u8>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub transport: Vec<Transport>,
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

impl Serialize for AuthenticatorSelection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AuthenticatorSelection", 4)?;

        if let Some(authenticator_attachment) = &self.authenticator_attachment {
            state.serialize_field("authenticatorAttachment", &authenticator_attachment)?;
        } else {
            state.skip_field("authenticatorAttachment")?;
        }
        state.serialize_field("residentKey", &self.resident_key)?;
        state.serialize_field("userVerification", &self.user_verification)?;
        state.serialize_field(
            "requireResidentKey",
            &(self.resident_key == Requirement::Required),
        )?;

        state.end()
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Requirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

// Not doing that yet
#[derive(Debug, Serialize)]
pub struct Extension {}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub raw_id: Vec<u8>,
    pub response: RegistrationResponseInner,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub client_extension_results: ExtensionResults,
    pub authenticator_attachment: AuthenticatorAttachment,
}

// Also not yet
#[derive(Debug, Deserialize)]
pub struct ExtensionResults {}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseInner {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub attestation_object: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,
    pub transports: Vec<Transport>,
    pub public_key_algorithm: Algorithm,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub public_key: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub authenticator_data: Vec<u8>,
}
