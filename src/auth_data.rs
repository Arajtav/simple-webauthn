use bytes::Buf;
use coset::{AsCborValue, CoseError, CoseKey};
use thiserror::Error;

pub fn decode_auth_data(mut buf: &[u8]) -> Result<AuthData, AuthDataError> {
    if buf.remaining() < 37 {
        return Err(AuthDataError::TooShort);
    }

    let mut rp_id_hash = [0u8; 32];

    buf.copy_to_slice(&mut rp_id_hash);

    let flags = Flags(buf.get_u8());
    let sign_count = buf.get_u32();

    let attested_credential = if flags.attested_credential_data() {
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

    let extensions = if flags.extension_data() {
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

#[derive(Debug)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: Flags,
    pub sign_count: u32,
    pub attested_credential: Option<AttestedCredential>,
    pub extensions: Option<ciborium::Value>,
}

#[derive(Debug, Clone, Copy)]
pub struct Flags(pub u8);

impl Flags {
    pub fn user_present(self) -> bool {
        self.0 & (1 << 0) != 0
    }

    pub fn user_verified(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    pub fn backup_state(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    pub fn backup_eligible(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    pub fn attested_credential_data(self) -> bool {
        self.0 & (1 << 6) != 0
    }

    pub fn extension_data(self) -> bool {
        self.0 & (1 << 7) != 0
    }
}

#[derive(Debug)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: CoseKey,
}
