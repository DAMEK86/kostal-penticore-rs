use std::fmt::Debug;
use serde::{Deserialize, Serialize};
use base64;
use rand::distributions::{Distribution, Uniform};
use rand::{rngs::OsRng, Rng, Error};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hmac;
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256 as SHA256};
use const_format::formatcp;
use std::num::NonZeroU32;
use const_format::pmr::respan_to;
use reqwest::header::{HeaderMap, CONTENT_TYPE, ACCEPT};


const NONCE_LENGTH: usize = 12;
const API_ROUTE: &str = "/api/v1";
const AUTH_START_EP: &str = formatcp!("{}{}", API_ROUTE, "/auth/start");
const AUTH_FINISH_EP: &str = formatcp!("{}{}", API_ROUTE, "/auth/finish");
const AUTH_CREATE_SESSION_EP: &str = formatcp!("{}{}", API_ROUTE, "/auth/create_session");

#[derive(Debug, Serialize, Deserialize)]
struct AuthClientFirst {
    /// Type of login: "user" or "master"
    username: String,
    /// Base64-coded random nonce of length 12 bytes
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthServerFirst {
    /// Base64-coded random nonce of server
    nonce: String,
    /// ID of authentication transaction
    #[serde(rename = "transactionId")]
    transaction_id: String,
    /// Rounds used for PBKDF2
    rounds: NonZeroU32,
    /// Salt used for PBKDF2
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthClientFinal {
    /// ID of authentication transaction
    #[serde(rename = "transactionId")]
    transaction_id: String,
    /// Base64-coded client proof
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthServerFinal {
    /// One-time usable token to create a session or set the user-password
    token: String,
    /// Base64-coded server signature
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthCreateSessionRequest {
    /// AES initialization vector
    iv: String,
    /// Only the token or token and service code (separated by colon). Encrypted with AES using the protocol key.
    payload: String,
    /// ID of authentication transaction
    #[serde(rename = "transactionId")]
    transaction_id: String,
    /// AES GCM tag
    tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthCreateSessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
}

pub struct Client<'a> {
    base_address: &'a str,
    user: &'a str,
    password: &'a str,
}

impl<'a> Client<'a> {
    pub fn new(base_address: &'a str, user: &'a str, password: &'a str) -> Self {
        Self {
            base_address,
            user,
            password,
        }
    }

    pub async fn get_server_trust(&self) -> Result<AuthServerFinal, Error> {
        // step1 create
        let nonce = Self::generate_nonce();
        let client_first_data = AuthClientFirst { username: "user".to_string(), nonce: base64::encode(nonce).into() };
        println!("{:#?}", client_first_data);
        let server_first_data = self.send_client_start_msg(&client_first_data).await?;
        println!("{:#?}", server_first_data);

        let auth_message = format!("n={},r={},r={},s={},i={},c=biws,r={}",
                                   self.user,
                                   client_first_data.nonce,
                                   server_first_data.nonce,
                                   server_first_data.salt,
                                   server_first_data.rounds,
                                   server_first_data.nonce);

        let client_proof = self.calculate_client_proof(&server_first_data, auth_message)?;

        let client_final_data = &AuthClientFinal {
            transaction_id: server_first_data.transaction_id,
            proof: base64::encode(client_proof).into()
        };

        self.send_client_final_msg(&client_final_data).await
    }

    fn calculate_client_proof(&self, server_first_data: &AuthServerFirst, auth_message: String) -> Result<[u8; 32], Error> {
        let salted_password = self.salt_password(&server_first_data.salt, server_first_data.rounds)?;
        let salted_password_signing_key = hmac::Key::new(hmac::HMAC_SHA256, &salted_password);
        let client_key = hmac::sign(&salted_password_signing_key, b"Client Key");
        let server_key = hmac::sign(&salted_password_signing_key, b"Server Key");

        let stored_key = ring::digest::digest(&ring::digest::SHA256, client_key.as_ref());
        let stored_key_signing_key = hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref());
        let client_signature = Client::sign_slice(&stored_key_signing_key, auth_message.as_bytes());
        let server_signature_signing_key = hmac::Key::new(hmac::HMAC_SHA256, server_key.as_ref());
        let server_signature = Client::sign_slice(&server_signature_signing_key, auth_message.as_bytes());
        let mut client_proof = [0u8; SHA256_OUTPUT_LEN];
        let xor_iter = client_key
            .as_ref()
            .iter()
            .zip(client_signature.as_ref())
            .map(|(k, s)| k ^ s);
        for (p, x) in client_proof.iter_mut().zip(xor_iter) {
            *p = x
        }
        Ok(client_proof)
    }

    async fn send_client_final_msg(&self, auth_client_final_data: &&AuthClientFinal) -> Result<AuthServerFinal, Error> {
        let resp = reqwest::Client::new()
            .post(format!("{}{}", self.base_address, AUTH_FINISH_EP))
            .json(&auth_client_final_data)
            .send()
            .await;
        let resp = match resp {
            Ok(resp) => resp.json::<AuthServerFinal>().await,
            Err(error) => return Err(Error::new(error))
        };
        let resp = match resp {
            Ok(resp) => resp,
            Err(error) => return Err(Error::new(error))
        };
        Ok(resp)
    }

    async fn send_client_start_msg(&self, data: &AuthClientFirst) -> Result<AuthServerFirst, Error> {
        let resp = reqwest::Client::new()
            .post(format!("{}{}", self.base_address, AUTH_START_EP))
            .json(&data)
            .send()
            .await;
        let resp = match resp {
            Ok(resp) => resp.json::<AuthServerFirst>().await,
            Err(error) => return Err(Error::new(error))
        };
        let resp = match resp {
            Ok(resp) => resp,
            Err(error) => return Err(Error::new(error))
        };
        Ok(resp)
    }

    fn generate_nonce() -> String {
        Uniform::from(33..125)
            .sample_iter(OsRng)
            .map(|x: u8| if x > 43 { (x + 1) as char } else { x as char })
            .take(NONCE_LENGTH)
            .collect()
    }

    fn salt_password(&self, salt: &String, rounds: NonZeroU32) -> Result<[u8; 32], Error> {
        let decoded_salt = base64::decode(salt);
        let decoded_salt = match decoded_salt {
            Ok(salt) => salt,
            Err(error) => return Err(Error::new(error))
        };
        Ok(self.hash_password(self.password, rounds, &decoded_salt))
    }

    fn hash_password(
        &self,
        password: &str,
        iterations: NonZeroU32,
        salt: &[u8],
    ) -> [u8; SHA256_OUTPUT_LEN] {
        let mut salted_password = [0u8; SHA256_OUTPUT_LEN];
        pbkdf2::derive(
            SHA256,
            iterations,
            salt,
            password.as_bytes(),
            &mut salted_password,
        );
        salted_password
    }

    fn sign_slice(key: &hmac::Key, slice: &[u8]) -> hmac::Tag {
        let mut signature_context = hmac::Context::with_key(key);
        signature_context.update(slice);
        signature_context.sign()
    }
}
