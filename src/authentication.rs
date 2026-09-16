use crate::{
    Authentication, Credential, Requirement,
    auth_data::{AuthDataError, decode_auth_data},
    shared::{ClientData, CredentialInfo, Hint, Response, generate_challenge, sha256},
};
use coset::{CoseKey, RegisteredLabel, RegisteredLabelWithPrivate};
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use thiserror::Error;

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    challenge: [u8; 32],
    timeout: i32,
    rp_id: String,
    allow_credentials: Vec<CredentialInfo>,
    user_verification: Requirement,
    hints: Vec<Hint>,
}

#[derive(Debug)]
pub struct AuthenticationState {
    challenge: [u8; 32],
    rp_id: String,
    origin: String,
    user_verification: Requirement,
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Invalid clientDataJSON: {0}")]
    InvalidClientDataJson(serde_json::Error),
    #[error("Invalid clientDataJSON type: {0}")]
    InvalidClientDataJsonType(String),
    #[error("Challenge mismatch, expected: {0:?}, got {1:?}")]
    ChallengeMismatch([u8; 32], Vec<u8>),
    #[error("Origin mismatch, expected: {0}, got {1}")]
    OriginMismatch(String, String),
    #[error("RP id hash mismatch, expected {0:?}, got {1:?}")]
    RpIdHashMismatch([u8; 32], [u8; 32]),
    #[error("User not present")]
    UserNotPresent,
    #[error("User verification required")]
    UserVerificationRequired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("No key found")]
    NoKeyFound,
    #[error("authData decoding failed: {0}")]
    AuthData(#[from] AuthDataError),
}

pub type AuthenticationResponse = Response<AuthenticationResponseInner>;

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponseInner {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    signature: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "clientDataJSON")]
    client_data_json: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    authenticator_data: Vec<u8>,
}

#[must_use]
pub fn start_authentication(
    rp_id: String,
    origin: String,
    user_verification: Requirement,
) -> (AuthenticationRequest, AuthenticationState) {
    let challenge = generate_challenge();

    let state = AuthenticationState {
        challenge,
        rp_id: rp_id.clone(),
        origin,
        user_verification,
    };

    let request = AuthenticationRequest {
        challenge,
        timeout: 60000,
        rp_id,
        allow_credentials: Vec::new(),
        user_verification: Requirement::Required,
        hints: Vec::new(),
    };

    (request, state)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCredential {
    key: CoseKey,
    id: Vec<u8>,
}

impl From<Credential> for SimpleCredential {
    fn from(cred: Credential) -> Self {
        Self {
            key: cred.public_key,
            id: cred.id,
        }
    }
}

pub fn verify_authentication(
    response: AuthenticationResponse,
    state: AuthenticationState,
    credentials: &[SimpleCredential],
) -> Result<Authentication, AuthenticationError> {
    let client_data: ClientData = serde_json::from_slice(&response.response.client_data_json)
        .map_err(AuthenticationError::InvalidClientDataJson)?;

    if client_data.ty != "webauthn.get" {
        return Err(AuthenticationError::InvalidClientDataJsonType(
            client_data.ty,
        ));
    }

    if client_data.challenge != state.challenge {
        return Err(AuthenticationError::ChallengeMismatch(
            state.challenge,
            client_data.challenge,
        ));
    }

    if client_data.origin != state.origin {
        return Err(AuthenticationError::OriginMismatch(
            client_data.origin,
            state.origin,
        ));
    }

    let auth_data = decode_auth_data(&response.response.authenticator_data)?;

    let expected_rp_id_hash = sha256(state.rp_id.as_bytes());

    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(AuthenticationError::RpIdHashMismatch(
            expected_rp_id_hash,
            auth_data.rp_id_hash,
        ));
    }

    if !auth_data.flags.user_present() {
        return Err(AuthenticationError::UserNotPresent);
    }

    if state.user_verification == Requirement::Required && !auth_data.flags.user_verified() {
        return Err(AuthenticationError::UserVerificationRequired);
    }

    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&response.response.authenticator_data);
    verification_data.extend_from_slice(&sha256(&response.response.client_data_json));

    let Some(credential) = credentials.iter().find(|cred| cred.id == response.id) else {
        return Err(AuthenticationError::NoKeyFound);
    };

    if !verify_cose_signature(
        &credential.key,
        &response.response.signature,
        &verification_data,
    ) {
        return Err(AuthenticationError::InvalidSignature);
    }

    Ok(Authentication {
        credential_id: response.id,
        user_verified: auth_data.flags.user_verified(),
        sign_count: auth_data.sign_count,
    })
}

fn verify_cose_signature(key: &CoseKey, signature: &[u8], message: &[u8]) -> bool {
    if key.kty != RegisteredLabel::Assigned(coset::iana::KeyType::EC2) {
        return false;
    }

    if key.alg
        != Some(RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256,
        ))
    {
        return false;
    }

    let Ok(public_key) = key.to_sec1_octet_string() else {
        return false;
    };

    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .is_ok()
}
