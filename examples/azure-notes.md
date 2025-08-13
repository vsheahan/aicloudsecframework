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

## Evidence Collection

**A1 Identity Evidence:**
```bash
# Verify managed identity
az identity show --name ai-agent-identity --resource-group ai-security-rg
```

**A5 Logging Evidence:**
```bash
# Query Azure OpenAI logs
az monitor log-analytics query --workspace workspace-id --analytics-query "CognitiveServicesAuditLogs | limit 10"
```