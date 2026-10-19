package analysis

import "fmt"

// AzureCredentials is a service-principal client secret for a read-only Azure
// analyzer (Reader + Key Vault Reader at subscription scope).
type AzureCredentials struct {
	SubscriptionID string `json:"subscription_id"`
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
}

func (c *AzureCredentials) Valid() error {
	if c.SubscriptionID == "" {
		return fmt.Errorf("azure credentials missing subscription_id")
	}
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("azure credentials missing tenant_id/client_id/client_secret")
	}
	return nil
}

// Azure resources captured by the collector (analysis-friendly subset).
type AzureStorageAccount struct {
	Name            string
	ResourceGroup   string
	PublicAccess    bool // allowBlobPublicAccess / allowNestedItemsToBePublic
	MinTLS          string
	InfraEncrypted  bool
}

type AzurePostgres struct {
	Name            string
	ResourceGroup   string
	PublicNetwork   bool
	ZoneRedundantHA bool
	BackupRetention int32
	GeoBackup       bool
	DeletionProtection bool
}

type AzureKeyVault struct {
	Name          string
	ResourceGroup string
	SoftDelete    bool
	PurgeProtect  bool
	PublicNetwork bool
}

type AzureVM struct {
	ResourceID string
	Name       string
	PublicIP   bool
}

type AzureNSG struct {
	Name         string
	ResourceGroup string
	Ingress      []AzureNSGRule
}

type AzureNSGRule struct {
	FromPort      int32
	ToPort        int32
	AllProtocol   bool
	PublicSource  bool // * or 0.0.0.0/0 or ::/0
}