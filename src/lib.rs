use bytes::Buf;
use coset::AsCborValue;
use coset::CoseError;
use coset::CoseKey;
use coset::RegisteredLabel;
use coset::RegisteredLabelWithPrivate;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use sha2::Digest;
use thiserror::Error;

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    challenge: Vec<u8>,
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
enum Attestation {
    None,
}

#[derive(Debug, Serialize)]
struct Hint {}

#[derive(Debug, Serialize)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    key_type: KeyType,
    alg: Algorithm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum KeyType {
    PublicKey,
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

#[serde_as]
#[derive(Debug, Serialize)]
struct SimpleCredential {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    id: Vec<u8>,
    #[serde(rename = "type")]
    key_type: KeyType,
    transport: Vec<Transport>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    Internal,
    Usb,
    Nfc,
    Ble,
    Hybrid,
    Cable,
}

#[derive(Debug)]
struct AuthenticatorSelection {
    authenticator_attachment: Option<AuthenticatorAttachment>,
    resident_key: Requirement,
    user_verification: Requirement,
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

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum Requirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

// Not doing that yet
#[derive(Debug, Serialize)]
struct Extension {}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response<R> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    id: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    raw_id: Vec<u8>,
    #[allow(clippy::struct_field_names)]
    response: R,
    #[serde(rename = "type")]
    key_type: KeyType,
    client_extension_results: ExtensionResults,
    authenticator_attachment: AuthenticatorAttachment,
}

pub type RegistrationResponse = Response<RegistrationResponseInner>;

// Also not yet
#[derive(Debug, Deserialize)]
pub struct ExtensionResults {}

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
    challenge: Vec<u8>,
    rp_id: String,
    origin: String,
    user_verification: Requirement,
    resident_key: Requirement,
}

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

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("Invalid clientDataJSON: {0}")]
    InvalidClientDataJson(serde_json::Error),
    #[error("Invalid clientDataJSON type: {0}")]
    InvalidClientDataJsonType(String),
    #[error("Challenge mismatch, expected: {0:?}, got {1:?}")]
    ChallengeMismatch(Vec<u8>, Vec<u8>),
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

#[must_use]
pub fn start_registration(
    rp: Rp,
    origin: String,
    user: User,
) -> (RegistrationRequest, RegistrationState) {
    let mut challenge = vec![0u8; 32];
    rand::rng().fill_bytes(&mut challenge);

    let state = RegistrationState {
        challenge: challenge.clone(),
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

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    challenge: Vec<u8>,
    origin: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationObject {
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: ciborium::Value,
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
            client_data.challenge,
            state.challenge,
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

    if !auth_data.flags.user_present {
        return Err(RegistrationError::UserNotPresent);
    }

    if state.user_verification == Requirement::Required && !auth_data.flags.user_verified {
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
        user_present: auth_data.flags.user_present,
        user_verified: auth_data.flags.user_verified,
        backup_state: auth_data.flags.backup_state,
        backup_eligible: auth_data.flags.backup_eligible,
    })
}

#[derive(Debug)]
pub struct AuthData {
    rp_id_hash: [u8; 32],
    flags: Flags,
    sign_count: u32,
    attested_credential: Option<AttestedCredential>,
    extensions: Option<ciborium::Value>,
}

#[derive(Debug)]
struct Flags {
    user_present: bool,
    user_verified: bool,
    backup_state: bool,
    backup_eligible: bool,
    attested_credential_data: bool,
    extension_data: bool,
}

impl From<u8> for Flags {
    fn from(flags: u8) -> Self {
        Self {
            user_present: flags & (1 << 0) != 0,
            user_verified: flags & (1 << 2) != 0,
            backup_state: flags & (1 << 3) != 0,
            backup_eligible: flags & (1 << 4) != 0,
            attested_credential_data: flags & (1 << 6) != 0,
            extension_data: flags & (1 << 7) != 0,
        }
    }
}

#[derive(Debug)]
struct AttestedCredential {
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key: CoseKey,
}

#[derive(Debug, Error)]
pub enum AuthDataError {
    #[error("Too short")]
    TooShort,
    #[error("Invalid CBOR")]
    InvalidCbor,
    #[error("Invalid credential public key: {0}")]
    InvalidCredentialPublicKey(CoseError),
    #[error("Too long")]
    TooLong,
}

pub fn decode_auth_data(bytes: &[u8]) -> Result<AuthData, AuthDataError> {
    if bytes.len() < 37 {
        return Err(AuthDataError::TooShort);
    }

    let mut buf = bytes;
    let mut rp_id_hash = [0u8; 32];

    buf.copy_to_slice(&mut rp_id_hash);

    let flags = Flags::from(buf.get_u8());
    let sign_count = buf.get_u32();

    let attested_credential = if flags.attested_credential_data {
        if buf.remaining() < 18 {
            return Err(AuthDataError::TooShort);
        }

        let mut aaguid = [0u8; 16];
        buf.copy_to_slice(&mut aaguid);

        let credential_id_len = buf.get_u16() as usize;

        if buf.remaining() < credential_id_len {
            return Err(AuthDataError::TooShort);
        }

        let credential_id = buf.copy_to_bytes(credential_id_len).to_vec();

        if buf.remaining() == 0 {
            return Err(AuthDataError::TooShort);
        }

        let mut cursor = std::io::Cursor::new(buf.chunk());

        let credential_public_key: ciborium::Value =
            ciborium::from_reader(&mut cursor).map_err(|_| AuthDataError::InvalidCbor)?;

        #[allow(clippy::cast_possible_truncation)]
        let key_len = cursor.position() as usize;
        buf.advance(key_len);

        // TODO: check if it actually matches what was requested.
        let credential_public_key = CoseKey::from_cbor_value(credential_public_key)
            .map_err(AuthDataError::InvalidCredentialPublicKey)?;

        Some(AttestedCredential {
            aaguid,
            credential_id,
            credential_public_key,
        })
    } else {
        None
    };

    let extensions = if flags.extension_data {
        if buf.is_empty() {
            return Err(AuthDataError::TooShort);
        }

        let mut cursor = std::io::Cursor::new(buf.chunk());

        let extensions: ciborium::Value =
            ciborium::from_reader(&mut cursor).map_err(|_| AuthDataError::InvalidCbor)?;

        #[allow(clippy::cast_possible_truncation)]
        let extension_len = cursor.position() as usize;
        buf.advance(extension_len);

        Some(extensions)
    } else {
        None
    };

    if buf.has_remaining() {
        return Err(AuthDataError::TooLong);
    }

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential,
        extensions,
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    challenge: Vec<u8>,
    timeout: i32,
    rp_id: String,
    allow_credentials: Vec<SimpleCredential>,
    user_verification: Requirement,
    hints: Vec<Hint>,
}

#[derive(Debug, Clone)]
pub struct AuthenticationState {
    challenge: Vec<u8>,
    rp_id: String,
    origin: String,
    user_verification: Requirement,
}

#[must_use]
pub fn start_authentication(
    rp_id: String,
    origin: String,
    user_verification: Requirement,
) -> (AuthenticationRequest, AuthenticationState) {
    let mut challenge = vec![0u8; 32];
    rand::rng().fill_bytes(&mut challenge);

    let state = AuthenticationState {
        challenge: challenge.clone(),
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

#[derive(Debug)]
pub struct Authentication {
    pub credential_id: Vec<u8>,
    pub sign_count: u32,
    pub user_verified: bool,
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Invalid clientDataJSON: {0}")]
    InvalidClientDataJson(serde_json::Error),
    #[error("Invalid clientDataJSON type: {0}")]
    InvalidClientDataJsonType(String),
    #[error("Challenge mismatch, expected: {0:?}, got {1:?}")]
    ChallengeMismatch(Vec<u8>, Vec<u8>),
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

pub fn verify_authentication(
    response: AuthenticationResponse,
    state: AuthenticationState,
    credentials: &[Credential],
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
            client_data.challenge,
            state.challenge,
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

    if !auth_data.flags.user_present {
        return Err(AuthenticationError::UserNotPresent);
    }

    if state.user_verification == Requirement::Required && !auth_data.flags.user_verified {
        return Err(AuthenticationError::UserVerificationRequired);
    }

    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&response.response.authenticator_data);
    verification_data.extend_from_slice(&sha256(&response.response.client_data_json));

    let Some(credential) = credentials
        .iter()
        .find(|cred| cred.credential_id == response.id)
    else {
        return Err(AuthenticationError::NoKeyFound);
    };

    if !verify_cose_signature(
        &credential.public_key,
        &response.response.signature,
        &verification_data,
    ) {
        return Err(AuthenticationError::InvalidSignature);
    }

    Ok(Authentication {
        credential_id: response.id,
        user_verified: auth_data.flags.user_verified,
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
