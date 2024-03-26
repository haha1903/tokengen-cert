use std::collections::HashMap;
use std::error::Error;
use std::fs::read;
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::Parser;
use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::SigningAlgorithm;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

use token::Header;

use crate::token::{AccessTokenResponse, aud, Payload};

mod token;

#[derive(Parser, Debug)]
#[command(
name = "Token Generator by Certificate for Azure",
version = "1.0",
author = "Hai Chang<haha1903@gmail.com>",
about = "Generates an Azure access token using a certificate for authentication."
)]
struct Args {
    /// Azure tenant ID
    #[arg(short, long)]
    tenant_id: String,

    /// Azure client ID
    #[arg(short = 'i', long)]
    client_id: String,

    /// Scope for the Azure service
    #[arg(short, long)]
    scope: String,

    /// Path to the private key PEM file
    #[arg(short = 'k', long)]
    key_path: String,

    /// Path to the certificate PEM file
    #[arg(short = 'c', long)]
    cert_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let tenant_id = args.tenant_id;
    let client_id = args.client_id;
    let scope = args.scope;
    let key_path = args.key_path;
    let cert_path = args.cert_path;

    let pem = read(Path::new(&key_path))?;
    let public_key_pem = read(Path::new(&cert_path))?;

    let algorithm = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::private_key_from_pem(&pem)?,
    };

    let header = Header::new(&public_key_pem)?;
    let payload = Payload::new(tenant_id.to_owned(), client_id.to_string());
    let header_json = serde_json::json!(header);
    let payload_json = serde_json::json!(payload);

    let header_base64 = BASE64_STANDARD.encode(header_json.to_string());
    let payload_base64 = BASE64_STANDARD.encode(payload_json.to_string());
    let result = algorithm.sign(&header_base64, &payload_base64).unwrap();
    let client_assertion = format!("{}.{}.{}", header_base64, payload_base64, result);

    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    params.insert("grant_type", "client_credentials");
    let all_scope = format!("openid profile offline_access {}", scope);
    params.insert("scope", &all_scope);
    params.insert("client_assertion", &client_assertion);
    params.insert("client_id", &client_id);

    let res = client.post(aud(tenant_id.to_owned()))
        .form(&params)
        .send()
        .await?;

    let x: AccessTokenResponse = res.json().await?;
    println!("{}", x.access_token);
    Ok(())
}
