# Bitwarden Vault Export Automation
This Python script automates the export of your Bitwarden vault, supporting both individual and organizational vaults. It uses the Bitwarden Python SDK and retrieves sensitive information (such as the master password, organization ID, and client credentials) securely from Bitwarden Secrets Manager. Configuration details such as API URLs, output file paths are managed via a `.env` file.

## Features

- Export individual or organizational vaults.
- Retrieve secrets securely from Bitwarden Secrets Manager using UUIDs.
- Supports JSON, CSV, or other formats for export.
- Configurable via a `.env` file.
- Ready for scheduling with cron jobs for automation.
- Avoids re-authentication if already logged in to the Bitwarden CLI.

## Requirements

- Python 3.8+
- A Bitwarden account with access to Secrets Manager.
- Access token for Bitwarden machine account.
- [Bitwarden Python SDK](https://pypi.org/project/bitwarden-sdk/)
- Bitwarden CLI installed on your machine.

## Installation

1. **Clone the Repository**:

```bash
git clone https://github.com/your-username/bitwarden-exporter.git
cd bitwarden-exporter
```

2. **Install Dependencies**:

Install the required Python packages:

```bash
pip install -r requirements.txt
```

3. **Create `.env` File**:

Copy the `.env.example` to a new `.env` file:

```bash
cp .env.example .env
```

Fill in the appropriate values in the `.env` file (API URLs, UUIDs, access tokens, etc.).

4. **Add Secrets to Bitwarden Secrets Manager**:

The sensitive information, such as your client ID, client secret, and master password, must be stored in Bitwarden Secrets Manager. Follow the official Bitwarden documentation to create and manage secrets:

[Bitwarden Secrets Manager Documentation](https://bitwarden.com/help/secrets/)

For each secret (Client ID, Client Secret, Master Password, Organization ID), you will receive a UUID, which you need to add to your `.env` file.

5. **Run the Script**:

Execute the script using:

```bash
python export.py
```

## Environment Variables

The script uses environment variables to store sensitive information and configurations. Here's an explanation of each:

| Variable              | Description                                                                                   |
|-----------------------|-----------------------------------------------------------------------------------------------|
| `API_URL`             | The Bitwarden API URL, usually `https://vault.bitwarden.com/api`.                             |
| `IDENTITY_URL`        | The Bitwarden Identity URL, usually `https://vault.bitwarden.com/identity`.                   |
| `ACCESS_TOKEN`        | The access token for authenticating the Bitwarden SDK.                                         |
| `STATE_FILE`          | The path to the state file used by the Bitwarden SDK to manage authentication sessions.       |
| `CLIENT_ID_UUID`      | The UUID for the Bitwarden Client ID stored in Secrets Manager.                                |
| `CLIENT_SECRET_UUID`  | The UUID for the Bitwarden Client Secret stored in Secrets Manager.                            |
| `MASTER_PASSWORD_UUID`| The UUID for the master password stored in Bitwarden Secrets Manager.                          |
| `ORGANIZATION_ID_UUID`| The UUID for the organization ID stored in Bitwarden Secrets Manager (for exporting organizational vaults). |
| `OUTPUT_FILE`         | The path where the vault export will be saved (e.g., `/path/to/output/vault_export.json`).     |
| `VAULT_FORMAT`        | The format for the vault export (`json`, `csv`, etc.).                                         |
| `BW_PATH`             | The full path to the `bw` executable (e.g., `/opt/homebrew/bin/bw`).                          |
| `IS_ORGANIZATION`     | Set to `true` if exporting organizational vaults, otherwise `false`.                          |

## Example `.env`

```plaintext
# Bitwarden API URL
API_URL=https://vault.bitwarden.com/api

# Bitwarden Identity URL
IDENTITY_URL=https://vault.bitwarden.com/identity

# Bitwarden Access Token (for authenticating the SDK)
ACCESS_TOKEN=your_access_token_here

# Path to the state file used by the SDK

# UUIDs for API credentials stored in Secrets Manager
CLIENT_ID_UUID="your_client_id_uuid_here"
CLIENT_SECRET_UUID="your_client_secret_uuid_here"
MASTER_PASSWORD_UUID="your_master_password_uuid_here"
ORGANIZATION_ID_UUID="your_organization_id_uuid_here"

# Path where the vault export should be saved
OUTPUT_FILE=/path/to/vault_export.json

# Format for the exported vault (json, csv, etc.)
VAULT_FORMAT=json

# Set to 'true' if exporting organizational vaults, otherwise 'false'
IS_ORGANIZATION=true

# Path to the bw executable
BW_PATH=/opt/homebrew/bin/bw
```

## Scheduling the Export with Cron

To schedule the export to run automatically at specific intervals (e.g., daily), you can add a cron job. Here's an example cron entry that runs the export every day at 2 AM:

```
0 2 * * * /path/to/python /path/to/export.py
```

Make sure the paths to the Python interpreter and `export.py` are correct for your environment.

## Troubleshooting

- Ensure that the `bw` CLI is installed and accessible in the path specified in the `.env` file.
- Make sure all UUIDs for secrets are correct and stored in Bitwarden Secrets Manager.
- If the vault fails to unlock, check that the master password is correctly stored and retrieved from Secrets Manager.
