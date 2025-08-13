# GCP Implementation Guide

This guide provides GCP-specific implementations for the AI Security Framework controls A1-A6.

## Key GCP Services for AI Security
- **Workload Identity Federation**: Secure service account authentication
- **VPC Service Controls**: Data perimeter and exfiltration protection  
- **Cloud Logging**: Centralized audit logging and retention
- **Cloud Monitoring**: Metrics and alerting
- **Security Command Center**: Security posture management
- **Vertex AI**: Model serving with built-in guardrails

---

## Control A1: Workload Identity for AI Agents

```hcl
# Google Service Account for AI Agent
resource "google_service_account" "ai_agent_sa" {
  account_id   = "ai-agent-service-account"
  display_name = "AI Agent Service Account"
  description  = "Service account for AI agent with least privilege"
  project      = var.project_id
}

# IAM binding with least privilege
resource "google_project_iam_member" "ai_agent_vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.ai_agent_sa.email}"
}

# Cloud Run service with Workload Identity
resource "google_cloud_run_v2_service" "ai_agent" {
  name     = "ai-agent-service"
  location = var.region
  project  = var.project_id

  template {
    service_account = google_service_account.ai_agent_sa.email
    
    containers {
      image = "gcr.io/${var.project_id}/ai-agent:latest"
      
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      
      env {
        name  = "TOKEN_LIFETIME"
        value = "900" # 15 minutes
      }
    }
  }

  labels = {
    purpose = "ai-agent-runtime"
    control = "a1"
  }
}
```

## Control A2: Budget Tracking with Firestore

```hcl
# Firestore database for tool usage tracking
resource "google_firestore_database" "tool_usage_db" {
  project     = var.project_id
  name        = "ai-tool-usage"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  labels = {
    purpose = "ai-tool-budget-tracking"
    control = "a2"
  }
}

# Budget alert policy
resource "google_billing_budget" "ai_agent_budget" {
  billing_account = var.billing_account
  display_name    = "AI Agent Budget"

  budget_filter {
    projects = [var.project_id]
    services = ["services/aiplatform.googleapis.com"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "500"
    }
  }

  threshold_rules {
    threshold_percent = 0.8
    spend_basis       = "CURRENT_SPEND"
  }
}
```

## Control A5: Cloud Logging and Audit

```hcl
# Cloud Logging bucket for AI audit logs
resource "google_logging_project_bucket_config" "ai_audit_logs" {
  project    = var.project_id
  location   = var.region
  bucket_id  = "ai-audit-logs"
  
  retention_days = 365
  locked         = true

  description = "Audit logs for AI agent activities"
}

# Log sink for Vertex AI API calls
resource "google_logging_project_sink" "vertex_ai_audit" {
  name        = "vertex-ai-audit-sink"
  project     = var.project_id
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.region}/buckets/ai-audit-logs"

  filter = <<EOF
protoPayload.serviceName="aiplatform.googleapis.com"
AND protoPayload.methodName=~".*predictions.*"
EOF

  unique_writer_identity = true
}
```

## Control A6: Network Security and Egress Controls

```hcl
# VPC Network with restricted egress
resource "google_compute_network" "ai_vpc" {
  name                    = "ai-agent-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "ai_subnet" {
  name          = "ai-agent-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.ai_vpc.id
  ip_cidr_range = "10.0.1.0/24"
  
  private_ip_google_access = true
}

# Firewall rules for egress control
resource "google_compute_firewall" "ai_egress_allow" {
  name    = "ai-egress-allow"
  project = var.project_id
  network = google_compute_network.ai_vpc.name

  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = [
    "199.36.153.8/30",  # Google APIs
    "199.36.153.4/30"   # Google APIs
  ]

  target_service_accounts = [
    google_service_account.ai_agent_sa.email
  ]
}

resource "google_compute_firewall" "ai_egress_deny" {
  name    = "ai-egress-deny"
  project = var.project_id
  network = google_compute_network.ai_vpc.name

  direction = "EGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]

  target_service_accounts = [
    google_service_account.ai_agent_sa.email
  ]
}
```

## Deployment Instructions

```bash
# 1. Initialize Terraform
terraform init

# 2. Authenticate with GCP
gcloud auth application-default login

# 3. Set required variables
export TF_VAR_project_id="your-project-id"
export TF_VAR_billing_account="your-billing-account"

# 4. Enable required APIs
gcloud services enable aiplatform.googleapis.com run.googleapis.com

# 5. Deploy infrastructure
terraform apply
```

## Control A4: Supply Chain Integrity with HashTraceAI

```hcl
# Cloud Storage bucket for model manifests
resource "google_storage_bucket" "model_manifests" {
  name     = "ai-model-manifests-${random_id.suffix.hex}"
  location = var.region
  project  = var.project_id

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.manifest_key.id
  }

  labels = {
    purpose = "ai-model-verification"
    control = "a4"
  }
}

# KMS key for manifest encryption
resource "google_kms_key_ring" "ai_security" {
  name     = "ai-security-keyring"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "manifest_key" {
  name     = "manifest-encryption-key"
  key_ring = google_kms_key_ring.ai_security.id

  purpose = "ENCRYPT_DECRYPT"

  labels = {
    purpose = "ai-manifest-encryption"
    control = "a4"
  }
}

# Cloud Function for model verification
resource "google_cloudfunctions2_function" "model_verification" {
  name        = "ai-model-verification"
  location    = var.region
  project     = var.project_id
  description = "Automated model integrity verification using HashTraceAI"

  build_config {
    runtime     = "python39"
    entry_point = "verify_model"
    
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_zip.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    available_memory   = "256Mi"
    timeout_seconds    = 300
    
    service_account_email = google_service_account.verification_sa.email
    
    environment_variables = {
      MANIFEST_BUCKET = google_storage_bucket.model_manifests.name
      PUBLIC_KEY_PATH = "gs://${google_storage_bucket.verification_keys.name}/public_key.pem"
      PROJECT_ID      = var.project_id
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.storage.object.v1.finalized"
    
    event_filters {
      attribute = "bucket"
      value     = var.approved_models_bucket
    }
    
    event_filters {
      attribute = "objectNamePrefix"
      value     = "models/"
    }
  }

  labels = {
    purpose = "ai-model-verification"
    control = "a4"
  }
}

# Service account for verification function
resource "google_service_account" "verification_sa" {
  account_id   = "ai-model-verification"
  display_name = "AI Model Verification Service Account"
  project      = var.project_id
}

# IAM bindings for verification function
resource "google_storage_bucket_iam_member" "verification_manifest_access" {
  bucket = google_storage_bucket.model_manifests.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.verification_sa.email}"
}

resource "google_storage_bucket_iam_member" "verification_models_access" {
  bucket = var.approved_models_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.verification_sa.email}"
}

resource "google_storage_bucket_iam_member" "verification_keys_access" {
  bucket = google_storage_bucket.verification_keys.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.verification_sa.email}"
}

# Storage bucket for verification keys
resource "google_storage_bucket" "verification_keys" {
  name     = "ai-verification-keys-${random_id.suffix.hex}"
  location = var.region
  project  = var.project_id

  labels = {
    purpose = "ai-verification-keys"
    control = "a4"
  }
}

# Storage bucket for function source code
resource "google_storage_bucket" "function_source" {
  name     = "ai-function-source-${random_id.suffix.hex}"
  location = var.region
  project  = var.project_id
}

# Upload function source code
resource "google_storage_bucket_object" "function_zip" {
  name   = "model-verification-function.zip"
  bucket = google_storage_bucket.function_source.name
  source = "model-verification-function.zip"
}
```

## HashTraceAI Cloud Function Implementation

```python
# main.py for Google Cloud Function
import json
import os
import tempfile
import subprocess
from datetime import datetime
from google.cloud import storage
from google.cloud import logging as gcp_logging
import functions_framework

# Initialize clients
storage_client = storage.Client()
logging_client = gcp_logging.Client()

@functions_framework.cloud_event
def verify_model(cloud_event):
    """
    Cloud Function to verify model integrity using HashTraceAI
    Triggered by Cloud Storage object creation events
    """
    # Extract event data
    event_data = cloud_event.data
    bucket_name = event_data["bucket"]
    object_name = event_data["name"]
    
    # Only process model files
    if not any(object_name.endswith(ext) for ext in ['.bin', '.safetensors', '.onnx']):
        return {"status": "skipped", "reason": "not a model file"}
    
    try:
        # Download the model file
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        
        with tempfile.NamedTemporaryFile() as temp_model:
            blob.download_to_filename(temp_model.name)
            
            # Look for corresponding manifest
            manifest_blob_name = f"{object_name}.manifest.json"
            
            try:
                manifest_blob = bucket.blob(manifest_blob_name)
                
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json') as temp_manifest:
                    manifest_content = manifest_blob.download_as_text()
                    temp_manifest.write(manifest_content)
                    temp_manifest.flush()
                    
                    # Verify using HashTraceAI
                    verification_result = verify_model_integrity(temp_model.name, temp_manifest.name)
                    
            except Exception as e:
                verification_result = {
                    'error': f'No manifest found for {object_name}: {str(e)}',
                    'control': 'A4',
                    'status': 'FAIL',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        # Log results to Cloud Logging
        log_entry = {
            'model_file': object_name,
            'verification_status': verification_result['status'],
            'control': 'A4',
            'timestamp': verification_result['timestamp'],
            'bucket': bucket_name
        }
        
        logger = logging_client.logger("ai-model-verification")
        logger.log_struct(log_entry, severity="INFO")
        
        return verification_result
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'model_file': object_name,
            'control': 'A4',
            'status': 'ERROR',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger = logging_client.logger("ai-model-verification")
        logger.log_struct(error_result, severity="ERROR")
        
        return error_result

def verify_model_integrity(model_path, manifest_path):
    """
    Use HashTraceAI to verify model integrity
    """
    try:
        # Download public key from Cloud Storage
        public_key_path = os.environ.get('PUBLIC_KEY_PATH')
        
        with tempfile.NamedTemporaryFile(suffix='.pem') as temp_key:
            # Download public key from GCS
            key_bucket_name = public_key_path.split('/')[2]
            key_object_name = '/'.join(public_key_path.split('/')[3:])
            
            key_bucket = storage_client.bucket(key_bucket_name)
            key_blob = key_bucket.blob(key_object_name)
            key_blob.download_to_filename(temp_key.name)
            
            cmd = [
                'python3', '/workspace/hashtraceai/cli.py', 'verify',
                '--manifest-file', manifest_path,
                '--public-key', temp_key.name,
                '--format', 'json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return {
                    'status': 'VERIFIED',
                    'output': result.stdout,
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'status': 'VERIFICATION_FAILED',
                    'error': result.stderr,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
    except subprocess.TimeoutExpired:
        return {
            'status': 'TIMEOUT',
            'error': 'Verification timeout after 60 seconds',
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
```

## Deployment Instructions for A4

```bash
# 1. Package HashTraceAI for Cloud Function
mkdir -p /tmp/gcp_function_package
cp -r hashtraceai/ /tmp/gcp_function_package/
cp main.py /tmp/gcp_function_package/
cat > /tmp/gcp_function_package/requirements.txt << 'EOF'
google-cloud-storage==2.10.0
google-cloud-logging==3.8.0
functions-framework==3.4.0
cryptography>=3.4.8
EOF

# 2. Create deployment package
cd /tmp/gcp_function_package
zip -r model-verification-function.zip .

# 3. Deploy using Terraform
terraform apply

# 4. Upload verification keys
gsutil cp verification_keys/public_key.pem gs://ai-verification-keys-bucket/
```

## Evidence Collection

**A1 Identity Evidence:**
```bash
# Verify service account
gcloud iam service-accounts describe ai-agent-service-account@${PROJECT_ID}.iam.gserviceaccount.com
```

**A4 Supply Chain Evidence:**
```bash
# Verify HashTraceAI function deployment
gcloud functions describe ai-model-verification --region=${REGION}

# Check recent model verifications
gcloud logging read "resource.type=cloud_function AND resource.labels.function_name=ai-model-verification" --limit=10

# Verify manifest storage
gsutil ls gs://ai-model-manifests-bucket/
```

**Create Model Manifest Example (GCP):**
```bash
# Generate manifest for approved model
cd /path/to/model
python3 /path/to/hashtraceai/cli.py generate \
  --path . \
  --created-by "Security Team" \
  --model-name "Production-Model-v1" \
  --model-version "1.0" \
  --sign-key private_key.pem

# Upload to Cloud Storage with manifest
gsutil cp model.bin gs://approved-models-bucket/models/
gsutil cp Production-Model-v1_1.0_manifest.json gs://approved-models-bucket/models/model.bin.manifest.json
```

**A5 Logging Evidence:**
```bash
# Query Vertex AI audit logs
gcloud logging read "resource.type=ai_platform_serving_service" --limit=10
```

**A6 Network Evidence:**
```bash
# Verify firewall rules
gcloud compute firewall-rules list --filter="network:ai-agent-vpc"
```