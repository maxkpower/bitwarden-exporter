import os
import subprocess
from dotenv import load_dotenv
from bitwarden_sdk import BitwardenClient, client_settings_from_dict

# Load environment variables from the .env file
load_dotenv()

# Bitwarden Secrets Manager API URLs and access token
api_url = os.getenv("API_URL")
identity_url = os.getenv("IDENTITY_URL")
access_token = os.getenv("ACCESS_TOKEN")
state_file = os.getenv("STATE_FILE")

# UUIDs for secrets stored in Secrets Manager
client_id_uuid = os.getenv("CLIENT_ID_UUID")
client_secret_uuid = os.getenv("CLIENT_SECRET_UUID")
master_password_uuid = os.getenv("MASTER_PASSWORD_UUID")

# Output path for the vault export
output_file = os.getenv("OUTPUT_FILE")

# Authenticate with Bitwarden Secrets Manager using access token
def authenticate_secrets_manager():
    client = BitwardenClient(
        client_settings_from_dict(
            {
                "apiUrl": api_url,
                "identityUrl": identity_url,
                "deviceType": "SDK",
                "userAgent": "Python Script",
            }
        )
    )
    client.auth().login_access_token(access_token, state_file)
    return client

# Retrieve a secret from Bitwarden Secrets Manager using UUID
def get_secret_by_uuid(client, secret_uuid):
    secret_response = client.secrets().get(secret_uuid)
    return secret_response.data.value if secret_response and secret_response.data else None

# Check if the user is already logged in
def check_logged_in():
    try:
        result = subprocess.run([os.getenv("BW_PATH"), "status"], check=True, stdout=subprocess.PIPE)
        output = result.stdout.decode("utf-8").strip()
        if "unlocked" in output or "locked" in output:
            print("Already logged in.")
            return True
        return False
    except subprocess.CalledProcessError:
        return False

# Unlock the vault and return the session key
def bw_unlock(master_password):
    try:
        # Load the path to the bw executable from .env
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found

        unlock_process = subprocess.run([bw_path, "unlock", "--passwordenv", "BW_MASTER_PASSWORD"], check=True, stdout=subprocess.PIPE, env={
            "BW_MASTER_PASSWORD": master_password
        })

        # Capture the session key from the unlock output
        output = unlock_process.stdout.decode("utf-8")
        session_key = None
        for line in output.splitlines():
            if line.startswith("export BW_SESSION="):
                session_key = line.split('"')[1]

        if session_key:
            os.environ["BW_SESSION"] = session_key
            print("Vault unlocked successfully.")
            return session_key
        else:
            print("Session key not found in unlock output.")
            exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error unlocking vault: {e}")
        exit(1)

# Export the vault data to a file
def export_vault(session_key):
    try:
        # Load the path to the bw executable from .env
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found

        # Run the export command
        subprocess.run([bw_path, "export", "--format", "json", "--output", output_file, "--session", session_key], check=True)
        print(f"Vault exported successfully to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error exporting vault: {e}")
        exit(1)

if __name__ == "__main__":
    # Authenticate Bitwarden Secrets Manager
    secrets_client = authenticate_secrets_manager()

    # Fetch API credentials and master password from Secrets Manager
    master_password = get_secret_by_uuid(secrets_client, master_password_uuid)

    # If the user is logged in, proceed directly to unlock and export
    if check_logged_in():
        # Unlock the vault with master password and export vault data
        session_key = bw_unlock(master_password)
        export_vault(session_key)
