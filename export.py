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

# Export settings
output_file = os.getenv("OUTPUT_FILE")
export_format = os.getenv("EXPORT_FORMAT", "json")  # Default to "json" if not set
export_password = os.getenv("EXPORT_PASSWORD")  # Password for encrypted exports (if any)

# Authenticate with Bitwarden Secrets Manager using access token
def authenticate_secrets_manager():
    print("🔑 Authenticating with Bitwarden Secrets Manager...")
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
    print("✅ Authenticated with Bitwarden Secrets Manager.")
    return client

# Retrieve a secret from Bitwarden Secrets Manager using UUID
def get_secret_by_uuid(client, secret_uuid):
    print(f"🔍 Fetching secret with UUID: {secret_uuid}")
    secret_response = client.secrets().get(secret_uuid)
    if secret_response and secret_response.data:
        print(f"✅ Secret {secret_uuid} retrieved successfully.")
        return secret_response.data.value
    else:
        print(f"❌ Failed to retrieve secret {secret_uuid}.")
        return None

# Check if the user is already logged in
def check_logged_in():
    try:
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found
        print(f"🔍 Checking login status using {bw_path}...")
        result = subprocess.run([bw_path, "status"], check=True, stdout=subprocess.PIPE)
        output = result.stdout.decode("utf-8").strip()
        if "unlocked" in output or "locked" in output:
            print("🔓 Already logged in.")
            return True
        print("🔒 Not logged in.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Error checking login status: {e}")
        return False

# Login to Bitwarden using API key by setting environment variables
def bw_login(client_id, client_secret):
    try:
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found
        print("🔑 Logging in to Bitwarden using API key (from Secrets Manager)...")
        
        # Set the required environment variables for API key login
        os.environ['BW_CLIENTID'] = client_id
        os.environ['BW_CLIENTSECRET'] = client_secret
        
        # Log in using the environment variables
        login_process = subprocess.run([bw_path, "login", "--apikey"], check=True)
        if login_process.returncode == 0:
            print("✅ Logged in successfully.")
            return True
        else:
            print("❌ Failed to log in.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during login: {e}")
        return False

# Unlock the vault and capture the session key using --passwordenv
def bw_unlock(master_password):
    try:
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found

        print(f"🔓 Unlocking the Bitwarden vault using environment variable...")
        
        # Set the master password in an environment variable
        os.environ["BW_MASTER_PASSWORD"] = master_password

        # Run the unlock command and capture both stdout and stderr for debugging
        unlock_process = subprocess.run(
            [bw_path, "unlock", "--passwordenv", "BW_MASTER_PASSWORD"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )

        # Capture the output
        output = unlock_process.stdout.decode("utf-8")
        error_output = unlock_process.stderr.decode("utf-8")

        # Search for session key in the output by extracting the part between quotes after BW_SESSION=
        session_key = None
        if 'export BW_SESSION=' in output:
            session_key = output.split('export BW_SESSION="')[1].split('"')[0]

        if session_key:
            os.environ["BW_SESSION"] = session_key
            print(f"✅ Vault unlocked successfully with session key: {session_key}")
            return session_key
        else:
            print("❌ Session key not found in unlock output.")
            exit(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error unlocking vault: {e}")
        exit(1)

# Export the vault data to a file using the session key
def export_vault(session_key):
    try:
        bw_path = os.getenv("BW_PATH", "bw")  # Default to "bw" if BW_PATH is not found
        is_organization = os.getenv("IS_ORGANIZATION", "false").lower() == "true"
        organization_id = os.getenv("ORGANIZATION_ID") if is_organization else None

        print(f"🚀 Exporting vault to {output_file}...")

        # Prepare the command with format and session key
        export_command = [
            bw_path, "export", 
            "--format", export_format, 
            "--output", output_file, 
            "--session", session_key
        ]

        # Add password flag if the export format is "encrypted_json" and an export password is provided
        if export_format == "encrypted_json" and export_password:
            export_command.extend(["--password", export_password])

        # Add organization ID if exporting an organizational vault
        if is_organization and organization_id:
            export_command.extend(["--organizationid", organization_id])

        # Run the export command
        subprocess.run(export_command, check=True)
        print(f"✅ Vault exported successfully to {output_file} 🎉")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error exporting vault: {e}")
        exit(1)
        
if __name__ == "__main__":
    print("🚀 Starting Bitwarden Vault Export Script...")

    # Authenticate Bitwarden Secrets Manager
    secrets_client = authenticate_secrets_manager()

    # Fetch API credentials and master password from Secrets Manager
    client_id = get_secret_by_uuid(secrets_client, client_id_uuid)
    client_secret = get_secret_by_uuid(secrets_client, client_secret_uuid)
    master_password = get_secret_by_uuid(secrets_client, master_password_uuid)

    if not client_id or not client_secret or not master_password:
        print("❌ Missing required secrets. Exiting.")
        exit(1)

    # If the user is not logged in, attempt to log in using secrets
    if not check_logged_in():
        if not bw_login(client_id, client_secret):
            print("❌ Failed to log in. Exiting.")
            exit(1)

    # Unlock the vault with master password and get session key
    session_key = bw_unlock(master_password)

    # Export the vault using the session key
    export_vault(session_key)
