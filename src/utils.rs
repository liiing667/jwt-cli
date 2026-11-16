use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::str::Utf8Error;

use jsonwebtoken::jwk;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JWTError {
    Internal(String),
    External(jsonwebtoken::errors::Error),
}

pub type JWTResult<T> = Result<T, JWTError>;

impl From<jsonwebtoken::errors::Error> for JWTError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        JWTError::External(value)
    }
}

impl From<Utf8Error> for JWTError {
    fn from(value: Utf8Error) -> Self {
        JWTError::Internal(value.to_string())
    }
}

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JWTError::Internal(err) => write!(f, "{err}"),
            JWTError::External(err) => write!(f, "{err}"),
        }
    }
}

pub fn slurp_file(file_name: String) -> Vec<u8> {
    let err_msg = format!("Unable to read file {file_name}");
    fs::read(file_name).unwrap_or_else(|_| panic!("{err_msg}"))
}

pub fn write_file(path: &Path, content: &[u8]) {
    write_file_atomic(path, content)
        .unwrap_or_else(|err| panic!("Unable to write file {}: {}", path.display(), err))
}

fn write_file_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        let file_type = metadata.file_type();
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "target exists and is a symlink or not a regular file",
            ));
        }
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output path"))?;
    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };

    let mut temp_path = None;
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(
            ".{}.jwt-cli.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        match fs::symlink_metadata(&candidate) {
            Ok(_) => continue,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                temp_path = Some(candidate);
                break;
            }
            Err(err) => return Err(err),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary file name",
        )
    })?;

    let result = write_temp_and_replace(&temp_path, path, content);
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_temp_and_replace(temp_path: &Path, path: &Path, content: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut temp_file = options.open(temp_path)?;
    temp_file.write_all(content)?;
    temp_file.sync_all()?;
    drop(temp_file);

    replace_file(temp_path, path)
}

#[cfg(unix)]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
}

#[cfg(not(unix))]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temp_path, path)
}

pub fn parse_duration_string(val: &str) -> Result<i64, String> {
    let mut base_val = val.replace(" ago", "");

    if val.starts_with('-') {
        base_val = base_val.replacen('-', "", 1);
    }

    match parse_duration::parse(&base_val) {
        Ok(parsed_duration) => {
            let is_past = val.starts_with('-') || val.contains("ago");
            let seconds = parsed_duration.as_secs() as i64;

            if is_past {
                Ok(-seconds)
            } else {
                Ok(seconds)
            }
        }
        Err(_) => Err(String::from(
            "must be a UNIX timestamp or systemd.time string",
        )),
    }
}

pub enum SecretType {
    Pem,
    Der,
    Jwks,
    B64,
    Plain,
}

pub fn get_secret_from_file_or_input(
    alg: &Algorithm,
    secret_string: &str,
) -> (Vec<u8>, SecretType) {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                (
                    slurp_file(strip_leading_symbol(secret_string)),
                    if secret_string.ends_with(".json") {
                        SecretType::Jwks
                    } else {
                        SecretType::Plain
                    },
                )
            } else if secret_string.starts_with("b64:") {
                (
                    secret_string
                        .chars()
                        .skip(4)
                        .collect::<String>()
                        .as_bytes()
                        .to_owned(),
                    SecretType::B64,
                )
            } else {
                (secret_string.as_bytes().to_owned(), SecretType::Plain)
            }
        }
        _ => {
            if secret_string.starts_with('@') {
                (
                    slurp_file(strip_leading_symbol(secret_string)),
                    get_secret_file_type(secret_string),
                )
            } else {
                // allows to read JWKS from argument (e.g. output of 'curl https://auth.domain.com/jwks.json')
                (secret_string.as_bytes().to_vec(), SecretType::Jwks)
            }
        }
    }
}

fn strip_leading_symbol(secret_string: &str) -> String {
    secret_string.chars().skip(1).collect::<String>()
}

fn get_secret_file_type(secret_string: &str) -> SecretType {
    if secret_string.ends_with(".pem") {
        SecretType::Pem
    } else if secret_string.ends_with(".json") {
        SecretType::Jwks
    } else {
        SecretType::Der
    }
}

pub fn decoding_key_from_jwks_secret(
    secret: &[u8],
    header: Option<Header>,
) -> JWTResult<DecodingKey> {
    if let Some(h) = header {
        return match parse_jwks(secret) {
            Some(jwks) => decoding_key_from_jwks(jwks, &h),
            None => Err(JWTError::Internal("Invalid jwks format".to_string())),
        };
    }
    Err(JWTError::Internal("Invalid jwt header".to_string()))
}

pub fn decoding_key_from_jwks(jwks: jwk::JwkSet, header: &Header) -> JWTResult<DecodingKey> {
    let kid = match &header.kid {
        Some(k) => k.to_owned(),
        None => {
            return Err(JWTError::Internal(
                "Missing 'kid' from jwt header".to_string(),
            ));
        }
    };

    let jwk = match jwks.find(&kid) {
        Some(j) => j,
        None => {
            return Err(JWTError::Internal(format!(
                "No jwk found for 'kid' {kid:?}",
            )));
        }
    };

    DecodingKey::from_jwk(jwk).map_err(jsonwebtoken::errors::Error::into)
}

fn parse_jwks(secret: &[u8]) -> Option<jwk::JwkSet> {
    serde_json::from_slice(secret).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn writes_file_atomically_with_owner_only_permissions() {
        let dir = TempDir::new("jwt-write").unwrap();
        let path = dir.path().join("token.jwt");

        write_file_atomic(&path, b"secret-claims").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"secret-claims");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // no temporary files are left behind
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn overwrites_existing_regular_file() {
        let dir = TempDir::new("jwt-write").unwrap();
        let path = dir.path().join("token.jwt");
        fs::write(&path, b"old").unwrap();

        write_file_atomic(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn refuses_symlink_target() {
        let dir = TempDir::new("jwt-write").unwrap();
        let real = dir.path().join("real.txt");
        fs::write(&real, b"original").unwrap();
        let link = dir.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real, &link).unwrap();

        assert!(write_file_atomic(&link, b"payload").is_err());
        assert_eq!(fs::read(&real).unwrap(), b"original");
    }

    #[test]
    fn refuses_non_regular_target() {
        let dir = TempDir::new("jwt-write").unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        assert!(write_file_atomic(&subdir, b"payload").is_err());
    }

    #[test]
    fn leaves_no_temp_files_on_failure() {
        let dir = TempDir::new("jwt-write").unwrap();
        let path = dir.path().join("missing").join("token.jwt");

        assert!(write_file_atomic(&path, b"payload").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn parses_systemd_time_string() {
        assert_eq!(parse_duration_string("5s").unwrap(), 5);
        assert_eq!(parse_duration_string("2 days").unwrap(), 60 * 60 * 24 * 2);
        assert_eq!(parse_duration_string("-5s").unwrap(), -5);
        assert_eq!(
            parse_duration_string("2 days ago").unwrap(),
            60 * 60 * 24 * -2
        );
    }
}
