use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{File, read};
use std::io::Read;
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::Parser;
use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::SigningAlgorithm;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use serde::Deserialize;

use token::Header;

use crate::token::{AccessTokenResponse, aud, Payload};

mod token;

#[derive(Parser, Debug, Default, Deserialize)]
#[command(
name = "Token Generator by Certificate for Azure",
version = "1.0",
author = "Hai Chang<haha1903@gmail.com>",
about = "Generates an Azure access token using a certificate for authentication."
)]
struct Args {
    /// Azure tenant ID
    #[arg(short, long)]
    tenant_id: Option<String>,

    /// Azure client ID
    #[arg(short = 'i', long)]
    client_id: Option<String>,

    /// Scope for the Azure service
    #[arg(short, long)]
    scope: Option<String>,

    /// Path to the private key PEM file
    #[arg(short = 'k', long)]
    key_path: Option<String>,

    /// Path to the certificate PEM file
    #[arg(short = 'c', long)]
    cert_path: Option<String>,
}

fn read_default_config() -> Result<Args, Box<dyn Error>> {
    let home_dir = env::var("HOME")?;
    let config_path = Path::new(&home_dir).join(".tokengen-cert");
    if config_path.exists() {
        let mut file = File::open(config_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let args: Args = serde_json::from_str(&contents)?;
        Ok(args)
    } else {
        Ok(Args::default())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let default_args = read_default_config()?;
    let args = Args::parse();

    let tenant_id = args.tenant_id.unwrap_or(default_args.tenant_id.unwrap());
    let client_id = args.client_id.unwrap_or(default_args.client_id.unwrap());
    let scope = args.scope.unwrap_or(default_args.scope.unwrap());
    let key_path = args.key_path.unwrap_or(default_args.key_path.unwrap());
    let cert_path = args.cert_path.unwrap_or(default_args.cert_path.unwrap());

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
