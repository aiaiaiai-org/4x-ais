// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Native passwords: NFC, 8–128 code points, Argon2id with a server pepper.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher as _, PasswordVerifier as _, Version,
    password_hash::SaltString,
};
use unicode_normalization::UnicodeNormalization as _;

const MIN_CODE_POINTS: usize = 8;
const MAX_CODE_POINTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Length,
    Whitespace,
}

#[derive(Clone)]
pub struct PasswordEngine {
    pepper: Vec<u8>,
}

impl PasswordEngine {
    pub fn new(pepper: &[u8]) -> Self {
        Self {
            pepper: pepper.to_vec(),
        }
    }

    fn argon(&self) -> Argon2<'_> {
        // OWASP's Argon2id baseline: 19 MiB, two passes, one lane.
        let params =
            Params::new(19 * 1024, 2, 1, None).expect("static Argon2 parameters are valid");
        Argon2::new_with_secret(&self.pepper, Algorithm::Argon2id, Version::V0x13, params)
            .expect("the pepper is a valid Argon2 secret")
    }

    /// The password as it will be hashed, or why it is refused.
    pub fn validate(&self, password: &str) -> Result<String, PolicyError> {
        let normalized: String = password.nfc().collect();
        let length = normalized.chars().count();
        if !(MIN_CODE_POINTS..=MAX_CODE_POINTS).contains(&length) {
            return Err(PolicyError::Length);
        }
        if normalized.trim() != normalized || normalized.chars().any(char::is_control) {
            return Err(PolicyError::Whitespace);
        }
        Ok(normalized)
    }

    pub fn hash(&self, normalized: &str) -> Option<String> {
        let salt = crate::crypto::random_bytes::<16>()?;
        let salt = SaltString::encode_b64(&salt).ok()?;
        self.argon()
            .hash_password(normalized.as_bytes(), &salt)
            .ok()
            .map(|hash| hash.to_string())
    }

    pub fn verify(&self, password: &str, encoded: &str) -> bool {
        let normalized: String = password.nfc().collect();
        PasswordHash::new(encoded).is_ok_and(|hash| {
            self.argon()
                .verify_password(normalized.as_bytes(), &hash)
                .is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_only_with_the_same_pepper() {
        let engine = PasswordEngine::new(b"a-pepper-that-is-at-least-32-bytes-long");
        let hash = engine
            .hash(&engine.validate("correct horse").unwrap())
            .unwrap();
        assert!(engine.verify("correct horse", &hash));
        assert!(!engine.verify("correct horsE", &hash));
        let other = PasswordEngine::new(b"another-pepper-at-least-32-bytes-long!!");
        assert!(!other.verify("correct horse", &hash));
    }

    #[test]
    fn enforces_the_policy() {
        let engine = PasswordEngine::new(b"a-pepper-that-is-at-least-32-bytes-long");
        assert_eq!(engine.validate("short"), Err(PolicyError::Length));
        assert_eq!(engine.validate(&"x".repeat(129)), Err(PolicyError::Length));
        assert_eq!(
            engine.validate(" padded password"),
            Err(PolicyError::Whitespace)
        );
        assert_eq!(
            engine.validate("tab\tinside!"),
            Err(PolicyError::Whitespace)
        );
        assert!(engine.validate("spaces inside are fine").is_ok());
    }
}
