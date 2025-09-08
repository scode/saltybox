use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const MAGIC_PREFIX: &str = "saltybox";
const V1_MAGIC: &str = "saltybox1:";

pub fn wrap(body: &[u8]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(body);
    format!("{}{}", V1_MAGIC, encoded)
}

#[derive(thiserror::Error, Debug)]
pub enum UnwrapError {
    #[error("input size smaller than magic marker; likely truncated")]
    Truncated,
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("input claims to be saltybox, but not a version we support")]
    WrongVersion,
    #[error("input unrecognized as saltybox data")]
    Unrecognized,
}

pub fn unwrap(varmored_body: &str) -> Result<Vec<u8>, UnwrapError> {
    if varmored_body.len() < V1_MAGIC.len() {
        return Err(UnwrapError::Truncated);
    }

    if let Some(armored_body) = varmored_body.strip_prefix(V1_MAGIC) {
        let body = URL_SAFE_NO_PAD.decode(armored_body)?;
        return Ok(body);
    }

    if varmored_body.starts_with(MAGIC_PREFIX) {
        return Err(UnwrapError::WrongVersion);
    }

    Err(UnwrapError::Unrecognized)
}

