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

## Evidence Collection

**A1 Identity Evidence:**
```bash
# Verify service account
gcloud iam service-accounts describe ai-agent-service-account@${PROJECT_ID}.iam.gserviceaccount.com
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