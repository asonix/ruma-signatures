//! Public and private key pairs.

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
};

use ring::signature::{Ed25519KeyPair as RingEd25519KeyPair, KeyPair as _};

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
    /// The public key.
    public_key: Vec<u8>,

    /// The private key.
    private_key: Vec<u8>,

    /// The version of the key pair.
    version: String,
}

impl Ed25519KeyPair {
    /// Initializes a new key pair.
    ///
    /// # Parameters
    ///
    /// * public_key: The public key of the key pair.
    /// * private_key: The private key of the key pair.
    /// * version: The "version" of the key used for this signature.
    ///   Versions are used as an identifier to distinguish signatures generated from different keys
    ///   but using the same algorithm on the same homeserver.
    ///
    /// # Errors
    ///
    /// Returns an error if the public and private keys provided are invalid for the implementing
    /// algorithm.
    pub fn new(public_key: &[u8], private_key: &[u8], version: String) -> Result<Self, Error> {
        if let Err(error) = RingEd25519KeyPair::from_seed_and_public_key(private_key, public_key) {
            return Err(Error::new(error.to_string()));
        }

        Ok(Self {
            public_key: public_key.to_owned(),
            private_key: private_key.to_owned(),
            version,
        })
    }

    /// Generates a new key pair.
    ///
    /// # Returns
    ///
    /// Returns a tuple of (private_key, public_key)
    ///
    /// # Errors
    ///
    /// Returns an error if the generation failed.
    pub fn generate() -> Result<(Vec<u8>, Vec<u8>), Error> {
        let seed: [u8; 32] = ring::rand::generate(&ring::rand::SystemRandom::new())
            .map_err(|e| Error::new(e.to_string()))?
            .expose();

        // this works because ring expects a 32-byte key (and will fail on non-32-byte keys)
        let ed25519keypair = RingEd25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let public_key: Vec<u8> = ed25519keypair.public_key().as_ref().to_vec();

        Ok((seed.to_vec(), public_key))
    }
}

impl KeyPair for Ed25519KeyPair {
    fn sign(&self, message: &[u8]) -> Signature {
        // Okay to unwrap because we verified the input in `new`.
        let ring_key_pair =
            RingEd25519KeyPair::from_seed_and_public_key(&self.private_key, &self.public_key)
                .unwrap();

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
            .field("public_key", &self.public_key)
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
