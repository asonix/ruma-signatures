//! Public and private key pairs.

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
};

use ring::signature::Ed25519KeyPair as RingEd25519KeyPair;

use crate::{signatures::Signature, Algorithm, Error};

/// A cryptographic key pair for digitally signing data.
pub trait KeyPair: Sized {
    /// Signs a JSON object.
    ///
    /// # Parameters
    ///
    /// * message: An arbitrary series of bytes to sign.
    fn sign(&self, message: &[u8]) -> Signature;
}

/// An Ed25519 key pair.
#[derive(Clone, PartialEq)]
pub struct Ed25519KeyPair {
    /// pkcs8 encoded Private/Public Key document
    /// The public key.
    document: Vec<u8>,

    /// The version of the key pair.
    version: String,
}

impl Ed25519KeyPair {
    /// Initializes a new key pair.
    ///
    /// # Parameters
    ///
    /// * document: PKCS8-formatted bytes containing the private & public keys.
    /// * version: The "version" of the key used for this signature.
    ///   Versions are used as an identifier to distinguish signatures generated from different keys
    ///   but using the same algorithm on the same homeserver.
    ///
    /// # Errors
    ///
    /// Returns an error if the public and private keys provided are invalid for the implementing
    /// algorithm.
    pub fn new(document: &[u8], version: String) -> Result<Self, Error> {
        if let Err(error) = RingEd25519KeyPair::from_pkcs8(document) {
            return Err(Error::new(error.to_string()));
        }

        Ok(Self {
            document: document.to_owned(),
            version,
        })
    }

    /// Generates a new key pair.
    ///
    /// # Returns
    ///
    /// Returns a Vec<u8> representing a pkcs8-encoded private/public keypair
    ///
    /// # Errors
    ///
    /// Returns an error if the generation failed.
    pub fn generate() -> Result<Vec<u8>, Error> {
        let document = RingEd25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(document.as_ref().to_vec())
    }
}

impl KeyPair for Ed25519KeyPair {
    fn sign(&self, message: &[u8]) -> Signature {
        // Okay to unwrap because we verified the input in `new`.
        let ring_key_pair = RingEd25519KeyPair::from_pkcs8(&self.document).unwrap();

        Signature {
            algorithm: Algorithm::Ed25519,
            signature: ring_key_pair.sign(message).as_ref().to_vec(),
            version: self.version.clone(),
        }
    }
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_struct("Ed25519KeyPair")
            .field("version", &self.version)
            .finish()
    }
}

/// A map from entity names to sets of public keys for that entity.
///
/// "Entity" is generally a homeserver, e.g. "example.com".
pub type PublicKeyMap = HashMap<String, PublicKeySet>;

/// A set of public keys for a single homeserver.
///
/// This is represented as a map from key ID to Base64-encoded signature.
pub type PublicKeySet = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::Ed25519KeyPair;

    #[test]
    fn generate_key() {
        Ed25519KeyPair::generate().unwrap();
    }
}
