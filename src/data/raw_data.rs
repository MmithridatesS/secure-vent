use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey, Signer};
use sha2::{Sha512, Digest};
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use rand::{rngs::OsRng, TryRngCore};
use std::sync::Arc;

#[derive(Debug)]
struct Payload(Vec<u8>);


#[derive(Debug)]
struct RawData {
    nonce: [u8;12],
    content: Vec<u8>,
}

impl RawData {
    fn decrypt(self, cipher: Arc<Aes256Gcm>) -> SignedData {
        let nonce = Nonce::from_slice(&self.nonce);
        let signed_data = cipher.decrypt(nonce, &*self.content).unwrap();
        SignedData::from(signed_data)
    }
}

// For getting the data from link
impl From<Vec<u8>> for RawData {
    fn from(value: Vec<u8>) -> Self {
        let len = value.len();
        assert!(len > 28, "Length of value should be greater than 28");
        let mut nonce = [0; 12];
        nonce.clone_from_slice(&value[..12]);
        Self {
            nonce,
            content: value[12..len-16].to_vec(),
        }
    }
}

// For putting the data to link
impl From<RawData> for Vec<u8> {
    fn from(value: RawData) -> Self {
        let mut serialized = Vec::from(value.nonce);
        serialized.extend(value.content);
        serialized
    }
}


#[derive(Debug)]
struct SignedData{
    data: Vec<u8>,
    signature: [u8; 64],
    key: [u8; 32]
}

enum Auth {
    Verified(Vec<u8>),
    Unverified
}

impl SignedData {
    // drops self
    fn verify_signature(self) -> Auth {
        let pub_key = VerifyingKey::from_bytes(&self.key).unwrap();
        let signature = Signature::from_bytes(&self.signature);
        let mut data_hash = Sha512::new();
        data_hash.update(&self.data);
        let hashed_value = data_hash.finalize();
        if let Ok(()) = pub_key.verify(&hashed_value, &signature) {
            return Auth::Verified(self.data);
        }
        Auth::Unverified
    }


    fn encrypt(self, cipher: Arc<Aes256Gcm>) -> RawData {
        let mut nonce_bytes = [0u8; 12];
        if let Err(e) = OsRng.try_fill_bytes(&mut nonce_bytes) {
            panic!("{e}");
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let sd_bytes: Vec<u8> = self.into();
        RawData {
            nonce: nonce_bytes,
            content: cipher.encrypt(nonce, sd_bytes.as_ref()).unwrap()
        }
    }
}


impl Auth {
    fn sign(self, signing_key: SigningKey) -> SignedData {
        match self {
            Auth::Verified(data) => {
                let signature = signing_key.sign(&data).to_bytes();
                let key: [u8; 32] = signing_key.verifying_key().to_bytes();
                SignedData {
                    data,
                    signature,
                    key
                }
            }
            Auth::Unverified => todo!()
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_encryption_decryption() {
        let key = Key::<Aes256Gcm>::from_slice(b"asdasdasdasdasddasdasdasdasdasdd");
        let plaintext = b"Hello, world!";
        let cipher = Arc::new(Aes256Gcm::new(key));
        let rd = SignedData::encrypt(plaintext.to_vec(), cipher.clone()).unwrap();
        let res = rd.decrypt(cipher);
        assert_eq!(res.data, b"Hello, world!");
    }


}



impl From<SignedData> for Vec<u8> {
    fn from(value: SignedData) -> Self {
        let mut bytes = vec![];
        bytes.extend(&value.data);
        bytes.extend(&value.signature);
        bytes.extend(&value.key);
        bytes
    }
}
impl From<Vec<u8>> for SignedData{
    fn from(value: Vec<u8>) -> Self {
        let len = value.len();
        let mut key = [0u8; 32];
        let mut signature = [0u8; 64];
        key.clone_from_slice(&value[len-32..]);
        signature.clone_from_slice(&value[len-96..len-32]);

        Self {
            data: value[..len-96].to_vec(),
            key, 
            signature
        }
    }
    // fn to_bytes(&self) -> Vec<u8> {
    // }
}
