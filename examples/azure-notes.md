# Azure Implementation Guide

This guide provides Azure-specific implementations for the AI Security Framework controls A1-A6.

## Key Azure Services for AI Security
- **Managed Identity**: For agent authentication without credentials
- **Private Endpoints**: Secure network access to Azure AI services
- **Azure Monitor**: Centralized logging and alerting
- **Microsoft Defender for Cloud**: Security posture management
- **Microsoft Sentinel**: SIEM for threat detection
- **Cost Management**: Budget controls and anomaly detection

---

## Control A1: Managed Identity for AI Agents

```hcl
# Terraform for Azure Managed Identity
resource "azurerm_user_assigned_identity" "ai_agent_identity" {
  name                = "ai-agent-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = {
    Purpose = "AI-Agent-Identity"
    Control = "A1"
  }
}

# Role assignment with least privilege
resource "azurerm_role_assignment" "ai_agent_cognitive_user" {
  scope                = azurerm_cognitive_account.openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_user_assigned_identity.ai_agent_identity.principal_id
}

# Container instance with managed identity
resource "azurerm_container_group" "ai_agent" {
  name                = "ai-agent-container"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ai_agent_identity.id]
  }

  container {
    name   = "ai-agent"
    image  = "your-registry/ai-agent:latest"
    cpu    = "1"
    memory = "2"

    environment_variables = {
      AZURE_CLIENT_ID = azurerm_user_assigned_identity.ai_agent_identity.client_id
      TOKEN_LIFETIME  = "900" # 15 minutes
    }
  }

  tags = {
    Purpose = "AI-Agent-Runtime"
    Control = "A1"
  }
}
```

## Control A2: Budget Tracking with Cosmos DB

```hcl
# Cosmos DB for tool usage tracking
resource "azurerm_cosmosdb_account" "tool_usage_db" {
  name                = "ai-tool-usage-db"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }

  tags = {
    Purpose = "AI-Tool-Budget-Tracking"
    Control = "A2"
  }
}

resource "azurerm_cosmosdb_sql_container" "sessions" {
  name                = "sessions"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.tool_usage_db.name
  database_name       = azurerm_cosmosdb_sql_database.tool_usage.name
  partition_key_path  = "/session_id"

  default_ttl = 86400 # 24 hours auto-cleanup

  tags = {
    Purpose = "AI-Session-Tracking"
    Control = "A2"
  }
}
```

## Control A5: Azure Monitor and Log Analytics

```hcl
# Log Analytics workspace for centralized logging
resource "azurerm_log_analytics_workspace" "ai_logs" {
  name                = "ai-security-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 365

  tags = {
    Purpose = "AI-Security-Logging"
    Control = "A5"
  }
}

# Diagnostic settings for Azure OpenAI
resource "azurerm_monitor_diagnostic_setting" "openai_diagnostics" {
  name               = "openai-diagnostics"
  target_resource_id = azurerm_cognitive_account.openai.id

  log_analytics_workspace_id = azurerm_log_analytics_workspace.ai_logs.id

  enabled_log {
    category = "Audit"
  }

  enabled_log {
    category = "RequestResponse"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }

  tags = {
    Purpose = "AI-API-Auditing"
    Control = "A5"
  }
}
```

## Control A6: Network Security and Cost Controls

```hcl
# Virtual Network with restricted outbound access
resource "azurerm_virtual_network" "ai_vnet" {
  name                = "ai-agent-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Purpose = "AI-Network-Isolation"
    Control = "A6"
  }
}

# Network Security Group with restrictive rules
resource "azurerm_network_security_group" "ai_nsg" {
  name                = "ai-agent-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow HTTPS to Azure services
  security_rule {
    name                       = "allow-azure-services"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "AzureCloud"
  }

  # Deny all other outbound traffic
  security_rule {
    name                       = "deny-all-outbound"
    priority                   = 4096
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Purpose = "AI-Network-Security"
    Control = "A6"
  }
}

# Budget with alerts
resource "azurerm_consumption_budget_resource_group" "ai_budget" {
  name              = "ai-agent-budget"
  resource_group_id = azurerm_resource_group.main.id

  amount     = 500
  time_grain = "Monthly"

  notification {
    enabled   = true
    threshold = 80
    operator  = "GreaterThan"

    contact_emails = [
      var.security_team_email
    ]
  }

  tags = {
    Purpose = "AI-Cost-Monitoring"
    Control = "A6"
  }
}
```

## Deployment Instructions

```bash
# 1. Initialize Terraform
terraform init

# 2. Login to Azure
az login

# 3. Set required variables
export TF_VAR_security_team_email="security@yourcompany.com"

# 4. Deploy
terraform apply
```

## Control A4: Supply Chain Integrity with HashTraceAI

```hcl
# Storage Account for model manifests
resource "azurerm_storage_account" "model_manifests" {
  name                     = "aimodelmanifests${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  blob_properties {
    versioning_enabled = true
  }

  tags = {
    Purpose = "AI-Model-Verification"
    Control = "A4"
  }
}

resource "azurerm_storage_container" "manifests" {
  name                  = "manifests"
  storage_account_name  = azurerm_storage_account.model_manifests.name
  container_access_type = "private"
}

# Function App for model verification
resource "azurerm_service_plan" "verification_plan" {
  name                = "ai-verification-plan"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = {
    Purpose = "AI-Model-Verification"
    Control = "A4"
  }
}

resource "azurerm_linux_function_app" "model_verification" {
  name                = "ai-model-verification-${random_id.suffix.hex}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  storage_account_name       = azurerm_storage_account.model_manifests.name
  storage_account_access_key = azurerm_storage_account.model_manifests.primary_access_key
  service_plan_id            = azurerm_service_plan.verification_plan.id

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.verification_identity.id]
  }

  site_config {
    application_stack {
      python_version = "3.9"
    }
  }

  app_settings = {
    "MANIFEST_STORAGE_ACCOUNT" = azurerm_storage_account.model_manifests.name
    "PUBLIC_KEY_URL"          = "https://${azurerm_storage_account.model_manifests.name}.blob.core.windows.net/keys/public_key.pem"
    "FUNCTIONS_WORKER_RUNTIME" = "python"
  }

  tags = {
    Purpose = "AI-Model-Verification"
    Control = "A4"
  }
}

# Managed Identity for Function App
resource "azurerm_user_assigned_identity" "verification_identity" {
  name                = "ai-verification-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = {
    Purpose = "AI-Model-Verification"
    Control = "A4"
  }
}

# Role assignments for verification function
resource "azurerm_role_assignment" "verification_storage_blob_data" {
  scope                = azurerm_storage_account.model_manifests.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.verification_identity.principal_id
}

resource "azurerm_role_assignment" "verification_approved_models" {
  count                = var.approved_models_storage_account != "" ? 1 : 0
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.approved_models_resource_group}/providers/Microsoft.Storage/storageAccounts/${var.approved_models_storage_account}"
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.verification_identity.principal_id
}

# Event Grid subscription for blob creation events
resource "azurerm_eventgrid_event_subscription" "model_upload_trigger" {
  name  = "ai-model-upload-trigger"
  scope = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.approved_models_resource_group}/providers/Microsoft.Storage/storageAccounts/${var.approved_models_storage_account}"

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.model_verification.id}/functions/ModelVerification"
  }

  included_event_types = ["Microsoft.Storage.BlobCreated"]

  subject_filter {
    subject_ends_with = [".bin", ".safetensors", ".onnx"]
  }

  tags = {
    Purpose = "AI-Model-Verification-Trigger"
    Control = "A4"
  }
}
```

## HashTraceAI Function Implementation (Azure Functions)

```python
# __init__.py for Azure Function
import logging
import json
import os
from azure.functions import HttpRequest, HttpResponse
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
import tempfile
import subprocess
from datetime import datetime

def main(req: HttpRequest) -> HttpResponse:
    """
    Azure Function to verify model integrity using HashTraceAI
    """
    logging.info('Python HTTP trigger function processed a request.')
    
    try:
        # Parse Event Grid event
        req_body = req.get_json()
        if not req_body:
            return HttpResponse("Invalid request body", status_code=400)
        
        # Extract blob details from Event Grid event
        event_data = req_body[0]["data"]
        blob_url = event_data["url"]
        storage_account = event_data["url"].split("//")[1].split(".")[0]
        container_name = event_data["url"].split("/")[-2]
        blob_name = event_data["url"].split("/")[-1]
        
        # Initialize Azure credential and blob client
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(
            account_url=f"https://{storage_account}.blob.core.windows.net",
            credential=credential
        )
        
        # Download the model file
        with tempfile.NamedTemporaryFile() as temp_model:
            blob_client = blob_service_client.get_blob_client(
                container=container_name, 
                blob=blob_name
            )
            blob_data = blob_client.download_blob()
            temp_model.write(blob_data.readall())
            temp_model.flush()
            
            # Look for corresponding manifest
            manifest_blob_name = f"{blob_name}.manifest.json"
            
            try:
                manifest_client = blob_service_client.get_blob_client(
                    container=container_name,
                    blob=manifest_blob_name
                )
                
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json') as temp_manifest:
                    manifest_data = manifest_client.download_blob()
                    temp_manifest.write(manifest_data.readall().decode('utf-8'))
                    temp_manifest.flush()
                    
                    # Verify using HashTraceAI
                    verification_result = verify_model_integrity(temp_model.name, temp_manifest.name)
                    
            except Exception as e:
                verification_result = {
                    'error': f'No manifest found for {blob_name}: {str(e)}',
                    'control': 'A4',
                    'status': 'FAIL',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        # Log results
        logging.info(json.dumps({
            'model_file': blob_name,
            'verification_status': verification_result['status'],
            'control': 'A4',
            'timestamp': verification_result['timestamp']
        }))
        
        return HttpResponse(
            json.dumps(verification_result),
            status_code=200 if verification_result['status'] == 'VERIFIED' else 400,
            mimetype="application/json"
        )
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'control': 'A4',
            'status': 'ERROR',
            'timestamp': datetime.utcnow().isoformat()
        }
        logging.error(json.dumps(error_result))
        
        return HttpResponse(
            json.dumps(error_result),
            status_code=500,
            mimetype="application/json"
        )

def verify_model_integrity(model_path, manifest_path):
    """
    Use HashTraceAI to verify model integrity
    """
    try:
        # Get public key from environment or storage
        public_key_url = os.environ.get('PUBLIC_KEY_URL')
        
        # Download public key
        with tempfile.NamedTemporaryFile(suffix='.pem') as temp_key:
            # In production, download from secure storage
            # For now, assume key is available locally
            
            cmd = [
                'python3', '/home/site/wwwroot/hashtraceai/cli.py', 'verify',
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
# 1. Package HashTraceAI for Azure Functions
mkdir -p /tmp/azure_function_package
cp -r hashtraceai/ /tmp/azure_function_package/
cp __init__.py /tmp/azure_function_package/
cp requirements.txt /tmp/azure_function_package/

# 2. Create function.json
cat > /tmp/azure_function_package/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["post"]
    },
    {
      "type": "http",
      "direction": "out",
      "name": "$return"
    }
  ]
}
EOF

# 3. Deploy using Azure CLI
az functionapp deployment source config-zip \
  --resource-group ai-security-rg \
  --name ai-model-verification-func \
  --src /tmp/azure_function_package.zip

# 4. Upload verification keys
az storage blob upload \
  --account-name aimodelmanifests \
  --container-name keys \
  --name public_key.pem \
  --file verification_keys/public_key.pem
```

## Evidence Collection

**A1 Identity Evidence:**
```bash
# Verify managed identity
az identity show --name ai-agent-identity --resource-group ai-security-rg
```

**A4 Supply Chain Evidence:**
```bash
# Verify HashTraceAI function deployment
az functionapp show --name ai-model-verification --resource-group ai-security-rg

# Check recent model verifications
az monitor log-analytics query \
  --workspace $(az monitor log-analytics workspace show --name ai-security-logs --resource-group ai-security-rg --query id -o tsv) \
  --analytics-query "FunctionAppLogs | where Message contains 'A4' | limit 10"

# Verify manifest storage
az storage blob list \
  --account-name aimodelmanifests \
  --container-name manifests
```

**Create Model Manifest Example (Azure):**
```bash
# Generate manifest for approved model
cd /path/to/model
python3 /path/to/hashtraceai/cli.py generate \
  --path . \
  --created-by "Security Team" \
  --model-name "Production-Model-v1" \
  --model-version "1.0" \
  --sign-key private_key.pem

# Upload to Azure Storage with manifest
az storage blob upload \
  --account-name approvedmodels \
  --container-name models \
  --name model.bin \
  --file model.bin

az storage blob upload \
  --account-name approvedmodels \
  --container-name models \
  --name model.bin.manifest.json \
  --file Production-Model-v1_1.0_manifest.json
```

**A5 Logging Evidence:**
```bash
# Query Azure OpenAI logs
az monitor log-analytics query --workspace workspace-id --analytics-query "CognitiveServicesAuditLogs | limit 10"
```