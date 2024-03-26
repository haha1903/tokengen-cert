# Azure Token Generator

## About
This Rust application is designed to simplify the process of obtaining Azure access tokens using client credentials. By leveraging JWT tokens and private/public keys, it securely authenticates and retrieves tokens necessary for interacting with various Azure services. This tool is ideal for server-to-server scenarios where automated access to Azure resources is required without user interaction.

## Features
- Command-line interface for easy use and automation.
- Supports Azure client credentials flow.
- Uses JWT for secure authentication with Azure AD.
- Retrieves access tokens to authenticate against Azure services.

## Prerequisites
Before you begin, ensure you have the following:
- Rust programming environment setup.
- OpenSSL installed on your system.
- Azure AD application with client ID, tenant ID, and scope configured.
- Private key PEM file and certificate PEM file for your Azure AD application.

## Installation
1. Clone the repository to your local machine:
   ```
   git clone <repository-url>
   ```
2. Navigate to the cloned directory:
   ```
   cd azure-token-generator
   ```
3. Build the application using Cargo:
   ```
   cargo build --release
   ```

## Usage
To use the application, run it with the required parameters as shown below:
```
cargo run -- --tenant-id <YOUR_TENANT_ID> --client-id <YOUR_CLIENT_ID> --scope <YOUR_SCOPE> --key-path <PATH_TO_PRIVATE_KEY_PEM> --cert-path <PATH_TO_CERTIFICATE_PEM>
```

### Parameters
- `--tenant-id`: Your Azure tenant ID.
- `--client-id`: Your Azure client ID.
- `--scope`: The scope for the Azure service you wish to access.
- `--key-path`: Path to your private key PEM file.
- `--cert-path`: Path to your certificate PEM file.

## Contributing
Contributions to improve Azure Token Generator are welcome. Please feel free to fork the repository, make changes, and submit pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
This tool is not officially associated with Microsoft Azure. Please use it responsibly and in accordance with Azure's terms of service.
