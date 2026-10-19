package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2/google"
	cloudasset "google.golang.org/api/cloudasset/v1"
	cloudkms "google.golang.org/api/cloudkms/v1"
	cloudresourcemanagerv3 "google.golang.org/api/cloudresourcemanager/v3"
	compute "google.golang.org/api/compute/v1"
	iam "google.golang.org/api/iam/v1"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
)

// ServiceAccountJSON is the subset of a GCP service account key we parse.
type ServiceAccountJSON struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri,omitempty"`
	Type        string `json:"type"`
}

func (sa *ServiceAccountJSON) raw() ([]byte, error) {
	return json.Marshal(sa)
}

var readScopes = []string{
	"https://www.googleapis.com/auth/devstorage.read_only",
	"https://www.googleapis.com/auth/sqlservice.readonly",
	"https://www.googleapis.com/auth/compute.readonly",
	"https://www.googleapis.com/auth/logging.read",
	"https://www.googleapis.com/auth/cloudkms.readonly",
	"https://www.googleapis.com/auth/cloud-platform.read-only",
}

// ResourceSet holds everything the analyzer inspects for one project.
type ResourceSet struct {
	ProjectID string
	AccountID string
	Warnings  []string

	Buckets           []*storage.Bucket
	BucketPolicies    map[string][]*storage.PolicyBindings
	SQLInstances      []*sqladmin.DatabaseInstance
	ComputeInstances  []*compute.Instance
	InstanceTemplates []*compute.InstanceTemplate
	Firewalls         []*compute.Firewall
	Subnets           []*compute.Subnetwork
	ProjectIAM        []*cloudresourcemanagerv3.Binding
	IAMPolicyWarn     string
	SAs               []*iam.ServiceAccount
	SAKeys            map[string][]*iam.ServiceAccountKey
	SAKeysWarn        string
	Sinks             []*logging.LogSink
	CryptoKeys        []*cloudkms.CryptoKey
	Secrets           []*secretmanager.Secret
	SecretPolicies    map[string][]*secretmanager.Binding

	// Cloud Asset Inventory depth.
	BigQueryDatasets []*cloudasset.ResourceSearchResult
	CloudRunServices []*cloudasset.ResourceSearchResult
	PubSubTopics     []*cloudasset.ResourceSearchResult
	PublicIAM        []*cloudasset.IamPolicySearchResult

	// AWS resources (collected via CollectAWS).
	AWSBuckets        []AWSBucket
	AWSRDS            []AWSRDSInstance
	AWSEC2            []AWSEC2Instance
	AWSSecurityGroups []AWSSecurityGroup
	AWSKMS            []AWSKMSKey
	AWSIAMUsers       []AWSIAMUser
	AWSCloudTrails    []AWSCloudTrail

	// Azure resources (collected via CollectAzure).
	AzureStorage   []AzureStorageAccount
	AzurePostgres  []AzurePostgres
	AzureKeyVaults []AzureKeyVault
	AzureVMs       []AzureVM
	AzureNSGs      []AzureNSG
}

func (rs *ResourceSet) warn(format string, args ...any) {
	rs.Warnings = append(rs.Warnings, fmt.Sprintf(format, args...))
}

func ParseServiceAccount(data []byte) (*ServiceAccountJSON, error) {
	var sa ServiceAccountJSON
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("invalid service account JSON: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("service account JSON is missing project_id/client_email/private_key")
	}
	return &sa, nil
}

func (sa *ServiceAccountJSON) client(ctx context.Context) (*http.Client, error) {
	raw, err := sa.raw()
	if err != nil {
		return nil, err
	}
	conf, err := google.JWTConfigFromJSON(raw, readScopes...)
	if err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return conf.Client(ctx), nil
}

// Collect gathers resources for the project using the SA's read-only scopes.
// Failures for individual services degrade to warnings instead of aborting.
func Collect(ctx context.Context, sa *ServiceAccountJSON) (*ResourceSet, error) {
	client, err := sa.client(ctx)
	if err != nil {
		return nil, err
	}
	rs := &ResourceSet{
		ProjectID:      sa.ProjectID,
		BucketPolicies: map[string][]*storage.PolicyBindings{},
		SAKeys:         map[string][]*iam.ServiceAccountKey{},
		SecretPolicies: map[string][]*secretmanager.Binding{},
	}

	if err := collectStorage(ctx, client, rs); err != nil {
		return rs, err
	}
	collectSQL(ctx, client, rs)
	collectCompute(ctx, client, rs)
	collectIAM(ctx, client, rs)
	collectLogging(ctx, client, rs)
	collectKMS(ctx, client, rs)
	collectSecrets(ctx, client, rs)
	collectAssetInventory(ctx, client, rs)
	return rs, nil
}

var _ = option.WithHTTPClient // ensure option import used
