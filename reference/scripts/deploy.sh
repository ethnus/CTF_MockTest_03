#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""
PREFIX="${PREFIX:-ethnus-mocktest-01}"
REGION="${REGION:-us-east-1}"

cd "$(dirname "$0")"

# Validate AWS credentials before proceeding
echo "validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials not configured or expired"
  echo "Please configure AWS CLI or check your AWS Academy Learner Lab session"
  exit 1
fi

# ensure terraform
if ! command -v terraform >/dev/null 2>&1; then
  echo "installing terraform..."
  mkdir -p "$HOME/bin"
  TFV="1.9.8"  # Updated to more recent stable version
  
  # Detect platform for correct Terraform download
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$OS" in
    linux|darwin) ;;
    *) echo "ERROR: Unsupported OS: $OS"; exit 1 ;;
  esac
  
  TF_URL="https://releases.hashicorp.com/terraform/${TFV}/terraform_${TFV}_${OS}_${ARCH}.zip"
  curl -sSLo /tmp/tf.zip "$TF_URL"
  unzip -o /tmp/tf.zip -d "$HOME/bin" >/dev/null
  export PATH="$HOME/bin:$PATH"
  echo "terraform $TFV installed for ${OS}/${ARCH}"
fi

# State management for ephemeral environments like AWS CloudShell
# This ensures Terraform state is persisted in the user's home directory,
# which survives CloudShell session restarts.
BAK_DIR="$HOME/.tfbak/CTF_MockTest_01"
STATE_FILE="terraform.tfstate"
STATE_LOCK_FILE=".terraform.lock.hcl"

# Function to restore state from backup
restore_state() {
  # Only restore if terraform has been initialized or if forced
  if [ -d "$BAK_DIR" ] && [ -f "$BAK_DIR/$STATE_FILE" ]; then
    echo "Restoring Terraform state from $BAK_DIR..."
    if [ -d ".terraform" ] || [ "$1" == "force" ]; then
        cp "$BAK_DIR/$STATE_FILE"* . 2>/dev/null
        if [ -f "$BAK_DIR/$STATE_LOCK_FILE" ]; then
            cp "$BAK_DIR/$STATE_LOCK_FILE" .
        fi
        echo "Restore complete."
    else
        echo "Skipping restore: .terraform directory not found. Run deploy first."
    fi
  fi
}

# Function to backup state
backup_state() {
  if [ -f "$STATE_FILE" ]; then
    echo "Backing up Terraform state to $BAK_DIR..."
    mkdir -p "$BAK_DIR"
    cp "$STATE_FILE"* "$BAK_DIR/" 2>/dev/null
    if [ -f "$STATE_LOCK_FILE" ]; then
        cp "$STATE_LOCK_FILE" "$BAK_DIR/"
    fi
    echo "Backup complete."
  fi
}

# Function to remove backup
remove_backup() {
  if [ -d "$BAK_DIR" ]; then
    echo "Removing Terraform state backup from $BAK_DIR..."
    rm -rf "$BAK_DIR"
    echo "Backup removed."
  fi
}

restore_state force

echo "init"
# Backup existing state file if it exists
if [ -f "terraform.tfstate" ]; then
  cp terraform.tfstate "terraform.tfstate.backup.$(date +%Y%m%d_%H%M%S)"
  echo "existing state file backed up"
fi
terraform init -no-color -upgrade >/dev/null

echo "apply"
echo "Applying Terraform configuration..."
terraform apply -auto-approve -compact-warnings -no-color | while IFS= read -r line; do
  if [[ "$line" =~ ^[[:space:]]*[a-zA-Z0-9_-]+\. ]]; then
    echo "📦 $line"
  elif [[ "$line" =~ (Creating|Modifying|Destroying) ]]; then
    echo "⚙️  $line"
  elif [[ "$line" =~ (Creation|Modification|Destruction).*complete ]]; then
    echo "✅ $line"
  elif [[ "$line" =~ ^Apply ]]; then
    echo "🎯 $line"
  else
    echo "$line"
  fi
done

if [ $? -ne 0 ]; then
  echo ""
  echo "ERROR: Terraform apply failed"
  echo "Try running: bash teardown.sh && bash deploy.sh"
  exit 1
fi

echo "summary"
terraform output -no-color summary

# Capture and export outputs
bash ../export-outputs.sh

echo "Done."

backup_state
