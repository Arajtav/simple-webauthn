use serde::{Deserialize, Serialize, ser::SerializeStruct};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use thiserror::Error;

use crate::{
    Credential, Requirement, User,
    auth_data::{AuthDataError, decode_auth_data},
    shared::{
        AuthenticatorSelection, ClientData, Hint, KeyType, Response, SimpleCredential, Transport,
        generate_challenge, sha256,
    },
};

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    challenge: [u8; 32],
    rp: Rp,
    user: User,
    timeout: i32,
    attestation: Attestation,
    hints: Vec<Hint>,
    pub_key_cred_params: Vec<PubKeyCredParam>,
    exclude_credentials: Vec<SimpleCredential>,
    authenticator_selection: AuthenticatorSelection,
    extensions: Vec<Extension>,
}

#[derive(Debug, Serialize)]
pub struct Rp {
    pub name: String,
    pub id: String,
}

// TODO
#[derive(Debug, Serialize)]
enum Attestation {
    None,
}

#[derive(Debug, Serialize)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    key_type: KeyType,
    alg: Algorithm,
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    ES256 = -7,
    // EdDSA = -8,
    // RS256 = -257,
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
            // -8 => Ok(Algorithm::EdDSA),
            // -257 => Ok(Algorithm::RS256),
            _ => Err(serde::de::Error::custom(format!(
                "unknown algorithm: {value}"
            ))),
        }
    }
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

// Not doing that yet
#[derive(Debug, Serialize)]
struct Extension {}

pub type RegistrationResponse = Response<RegistrationResponseInner>;

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseInner {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    attestation_object: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "clientDataJSON")]
    client_data_json: Vec<u8>,
    transports: Vec<Transport>,
    public_key_algorithm: Algorithm,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    public_key: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    authenticator_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RegistrationState {
    challenge: [u8; 32],
    rp_id: String,
    origin: String,
    user_verification: Requirement,
    resident_key: Requirement,
}

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("Invalid clientDataJSON: {0}")]
    InvalidClientDataJson(serde_json::Error),
    #[error("Invalid clientDataJSON type: {0}")]
    InvalidClientDataJsonType(String),
    #[error("Challenge mismatch, expected: {0:?}, got {1:?}")]
    ChallengeMismatch([u8; 32], Vec<u8>),
    #[error("Origin mismatch, expected: {0}, got {1}")]
    OriginMismatch(String, String),
    // I am not bothering with that cursed error handling
    #[error("Invalid attestationObject: {0}")]
    InvalidAttestationObject(String),
    #[error("RP id hash mismatch, expected {0:?}, got {1:?}")]
    RpIdHashMismatch([u8; 32], [u8; 32]),
    #[error("User not present")]
    UserNotPresent,
    #[error("User verification required")]
    UserVerificationRequired,
    #[error("Unexpected attestation")]
    UnexpectedAttestation,
    #[error("Invalid credential id")]
    InvalidCredentialId,
    #[error("Unsupported attestation format: {0}")]
    UnsupportedAttestationFmt(String),
    #[error("authData decoding failed: {0}")]
    AuthData(#[from] AuthDataError),
    #[error("credential data is missing")]
    CredentialDataMissing,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationObject {
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: ciborium::Value,
}

#[must_use]
pub fn start_registration(
    rp: Rp,
    origin: String,
    user: User,
) -> (RegistrationRequest, RegistrationState) {
    let challenge = generate_challenge();

    let state = RegistrationState {
        challenge,
        rp_id: rp.id.clone(),
        origin,
        user_verification: Requirement::Required,
        resident_key: Requirement::Required,
    };

    let request = RegistrationRequest {
        challenge,
        rp,
        user,
        timeout: 60000,
        attestation: Attestation::None,
        hints: Vec::new(),
        pub_key_cred_params: vec![
            // PubKeyCredParam {
            //     key_type: KeyType::PublicKey,
            //     alg: Algorithm::EdDSA,
            // },
            PubKeyCredParam {
                key_type: KeyType::PublicKey,
                alg: Algorithm::ES256,
            },
            // PubKeyCredParam {
            //     key_type: KeyType::PublicKey,
            //     alg: Algorithm::RS256,
            // },
        ],
        exclude_credentials: Vec::new(),
        authenticator_selection: AuthenticatorSelection {
            authenticator_attachment: None,
            resident_key: Requirement::Required,
            user_verification: Requirement::Required,
        },
        extensions: Vec::new(),
    };

    (request, state)
}

#[allow(clippy::needless_pass_by_value)]
pub fn verify_registration(
    response: RegistrationResponse,
    state: RegistrationState,
) -> Result<Credential, RegistrationError> {
    let client_data: ClientData = serde_json::from_slice(&response.response.client_data_json)
        .map_err(RegistrationError::InvalidClientDataJson)?;

    if client_data.ty != "webauthn.create" {
        return Err(RegistrationError::InvalidClientDataJsonType(client_data.ty));
    }

    if client_data.challenge != state.challenge {
        return Err(RegistrationError::ChallengeMismatch(
            state.challenge,
            client_data.challenge,
        ));
    }

    if client_data.origin != state.origin {
        return Err(RegistrationError::OriginMismatch(
            client_data.origin,
            state.origin,
        ));
    }

    let attestation: AttestationObject =
        ciborium::de::from_reader(response.response.attestation_object.as_slice())
            .map_err(|err| RegistrationError::InvalidAttestationObject(err.to_string()))?;

    let auth_data = decode_auth_data(&attestation.auth_data)?;

    let expected_rp_id_hash = sha256(state.rp_id.as_bytes());

    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(RegistrationError::RpIdHashMismatch(
            expected_rp_id_hash,
            auth_data.rp_id_hash,
        ));
    }

    if !auth_data.flags.user_present() {
        return Err(RegistrationError::UserNotPresent);
    }

    if state.user_verification == Requirement::Required && !auth_data.flags.user_verified() {
        return Err(RegistrationError::UserVerificationRequired);
    }

    let credential = auth_data
        .attested_credential
        .ok_or(RegistrationError::CredentialDataMissing)?;

    if credential.credential_id.is_empty() {
        return Err(RegistrationError::InvalidCredentialId);
    }

    if attestation.fmt != "none" {
        return Err(RegistrationError::UnsupportedAttestationFmt(
            attestation.fmt,
        ));
    }

    if !matches!(attestation.att_stmt, ciborium::Value::Map(map) if map.is_empty()) {
        return Err(RegistrationError::UnexpectedAttestation);
    }

    Ok(Credential {
        credential_id: credential.credential_id,
        public_key: credential.credential_public_key,
        sign_count: auth_data.sign_count,
        user_present: auth_data.flags.user_present(),
        user_verified: auth_data.flags.user_verified(),
        backup_state: auth_data.flags.backup_state(),
        backup_eligible: auth_data.flags.backup_eligible(),
    })
}
