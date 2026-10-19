package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// azureClient builds a credential + arm client options for the subscription.
func azureCred(ctx context.Context, creds *AzureCredentials) (*azidentity.ClientSecretCredential, *arm.ClientOptions, error) {
	cred, err := azidentity.NewClientSecretCredential(creds.TenantID, creds.ClientID, creds.ClientSecret, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("azure credential: %w", err)
	}
	opts := &arm.ClientOptions{}
	return cred, opts, nil
}

// CollectAzure gathers resources across the subscription using a read-only
// service principal. Failures per service degrade to warnings.
func CollectAzure(ctx context.Context, creds *AzureCredentials) (*ResourceSet, error) {
	cred, opts, err := azureCred(ctx, creds)
	if err != nil {
		return nil, err
	}
	rs := &ResourceSet{
		ProjectID:       creds.SubscriptionID,
		Warnings:        []string{},
		AzureStorage:    []AzureStorageAccount{},
		AzurePostgres:   []AzurePostgres{},
		AzureKeyVaults:  []AzureKeyVault{},
		AzureVMs:        []AzureVM{},
		AzureNSGs:       []AzureNSG{},
	}
	collectAzureStorage(ctx, cred, opts, creds.SubscriptionID, rs)
	collectAzurePostgres(ctx, cred, opts, creds.SubscriptionID, rs)
	collectAzureKeyVaults(ctx, cred, opts, creds.SubscriptionID, rs)
	collectAzureVMs(ctx, cred, opts, creds.SubscriptionID, rs)
	collectAzureNSGs(ctx, cred, opts, creds.SubscriptionID, rs)
	return rs, nil
}

func collectAzureStorage(ctx context.Context, cred *azidentity.ClientSecretCredential, opts *arm.ClientOptions, sub string, rs *ResourceSet) {
	client, err := armstorage.NewAccountsClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure storage client: %v", err)
		return
	}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			rs.warn("azure storage list: %v", err)
			return
		}
		for _, acc := range page.Value {
			infraEncrypted := false
			if acc.Properties != nil && acc.Properties.Encryption != nil {
				infraEncrypted = deref(acc.Properties.Encryption.RequireInfrastructureEncryption)
			}
			rs.AzureStorage = append(rs.AzureStorage, AzureStorageAccount{
				Name:          deref(acc.Name),
				ResourceGroup: resourceGroupFromID(deref(acc.ID)),
				PublicAccess:  acc.Properties != nil && deref(acc.Properties.AllowBlobPublicAccess),
				MinTLS:        string(deref(acc.Properties.MinimumTLSVersion)),
				InfraEncrypted: infraEncrypted,
			})
		}
	}
}

func collectAzurePostgres(ctx context.Context, cred *azidentity.ClientSecretCredential, opts *arm.ClientOptions, sub string, rs *ResourceSet) {
	client, err := armpostgresqlflexibleservers.NewServersClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure postgres client: %v", err)
		return
	}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			rs.warn("azure postgres list: %v", err)
			return
		}
		for _, srv := range page.Value {
			var retention int32
			var geoBackup bool
			if srv.Properties != nil && srv.Properties.Backup != nil {
				retention = deref(srv.Properties.Backup.BackupRetentionDays)
				geoBackup = deref(srv.Properties.Backup.GeoRedundantBackup) == armpostgresqlflexibleservers.GeoRedundantBackupEnumEnabled
			}
			ha := srv.Properties != nil && srv.Properties.HighAvailability != nil &&
				srv.Properties.HighAvailability.Mode != nil &&
				*srv.Properties.HighAvailability.Mode == armpostgresqlflexibleservers.HighAvailabilityModeZoneRedundant
			publicNetwork := srv.Properties != nil && srv.Properties.Network != nil &&
				deref(srv.Properties.Network.PublicNetworkAccess) == armpostgresqlflexibleservers.ServerPublicNetworkAccessStateEnabled

			rs.AzurePostgres = append(rs.AzurePostgres, AzurePostgres{
				Name:          deref(srv.Name),
				ResourceGroup: resourceGroupFromID(deref(srv.ID)),
				PublicNetwork: publicNetwork,
				ZoneRedundantHA: ha,
				BackupRetention: retention,
				GeoBackup:      geoBackup,
				DeletionProtection: false, // not exposed by this SDK version
			})
		}
	}
}

func collectAzureKeyVaults(ctx context.Context, cred *azidentity.ClientSecretCredential, opts *arm.ClientOptions, sub string, rs *ResourceSet) {
	rgClient, err := armresources.NewResourceGroupsClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure resource groups client: %v", err)
		return
	}
	vaultClient, err := armkeyvault.NewVaultsClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure keyvault client: %v", err)
		return
	}

	// Subscription-level vault list is stripped (no properties); list per group.
	rgPager := rgClient.NewListPager(nil)
	for rgPager.More() {
		rgPage, err := rgPager.NextPage(ctx)
		if err != nil {
			rs.warn("azure resource groups list: %v", err)
			return
		}
		for _, rg := range rgPage.Value {
			groupName := deref(rg.Name)
			pager := vaultClient.NewListByResourceGroupPager(groupName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					rs.warn("azure keyvault list in %s: %v", groupName, err)
					break
				}
				for _, v := range page.Value {
					props := v.Properties
					publicNetwork := false
					if props != nil && props.PublicNetworkAccess != nil && deref(props.PublicNetworkAccess) == "Enabled" {
						publicNetwork = true
					}
					if props != nil && props.NetworkACLs != nil && props.NetworkACLs.DefaultAction != nil {
						if *props.NetworkACLs.DefaultAction == armkeyvault.NetworkRuleActionAllow {
							publicNetwork = true
						}
					}
					rs.AzureKeyVaults = append(rs.AzureKeyVaults, AzureKeyVault{
						Name:          deref(v.Name),
						ResourceGroup: groupName,
						SoftDelete:    props != nil && deref(props.EnableSoftDelete),
						PurgeProtect:  props != nil && deref(props.EnablePurgeProtection),
						PublicNetwork: publicNetwork,
					})
				}
			}
		}
	}
}

func collectAzureVMs(ctx context.Context, cred *azidentity.ClientSecretCredential, opts *arm.ClientOptions, sub string, rs *ResourceSet) {
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure compute client: %v", err)
		return
	}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			rs.warn("azure vm list: %v", err)
			return
		}
		for _, vm := range page.Value {
			rs.AzureVMs = append(rs.AzureVMs, AzureVM{
				ResourceID: deref(vm.ID),
				Name:       deref(vm.Name),
				PublicIP:   vmHasPublicIP(vm),
			})
		}
	}
}

func vmHasPublicIP(vm *armcompute.VirtualMachine) bool {
	if vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return false
	}
	for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if nic != nil && nic.ID != nil && strings.Contains(*nic.ID, "public") {
			return true
		}
	}
	return false
}

func collectAzureNSGs(ctx context.Context, cred *azidentity.ClientSecretCredential, opts *arm.ClientOptions, sub string, rs *ResourceSet) {
	client, err := armnetwork.NewSecurityGroupsClient(sub, cred, opts)
	if err != nil {
		rs.warn("azure network client: %v", err)
		return
	}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			rs.warn("azure nsg list: %v", err)
			return
		}
		for _, nsg := range page.Value {
			group := AzureNSG{Name: deref(nsg.Name), ResourceGroup: resourceGroupFromID(deref(nsg.ID))}
			if nsg.Properties != nil {
				for _, r := range nsg.Properties.SecurityRules {
					if r == nil || r.Properties == nil || (r.Properties.Direction != nil && *r.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound) {
						continue
					}
					proto := deref(r.Properties.Protocol)
					rule := AzureNSGRule{
						AllProtocol: strings.EqualFold(string(proto), "*") ||
							strings.EqualFold(string(proto), "tcp") || strings.EqualFold(string(proto), "udp") || proto == "",
					}
					if r.Properties.SourceAddressPrefixes != nil {
						for _, p := range r.Properties.SourceAddressPrefixes {
							if deref(p) == "0.0.0.0/0" || deref(p) == "*" || deref(p) == "::/0" || deref(p) == "Internet" {
								rule.PublicSource = true
							}
						}
					}
					if r.Properties.SourceAddressPrefix != nil && (*r.Properties.SourceAddressPrefix == "0.0.0.0/0" ||
						*r.Properties.SourceAddressPrefix == "*" || *r.Properties.SourceAddressPrefix == "Internet") {
						rule.PublicSource = true
					}
					if r.Properties.DestinationPortRange != nil && r.Properties.DestinationPortRanges != nil {
						rule.FromPort = parsePort(deref(r.Properties.DestinationPortRange))
						rule.ToPort = rule.FromPort
					}
					group.Ingress = append(group.Ingress, rule)
				}
			}
			rs.AzureNSGs = append(rs.AzureNSGs, group)
		}
	}
}

func parsePort(s string) int32 {
	var out int32
	fmt.Sscanf(s, "%d", &out)
	return out
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if p == "resourceGroups" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func deref[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}