package analysis

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	cloudasset "google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/option"
)

// caiAssetTypes are the Cloud Asset Inventory asset types we search for depth
// beyond the dedicated collectors (their encryption posture comes from
// ResourceSearchResult.KmsKeys).
var caiAssetTypes = []string{
	"bigquery.googleapis.com/Dataset",
	"run.googleapis.com/Service",
	"pubsub.googleapis.com/Topic",
}

// collectAssetInventory uses Cloud Asset Inventory's search APIs to (a) deepen
// coverage with asset types we don't have dedicated collectors for, and
// (b) detect any IAM policy granting allUsers/allAuthenticatedUsers access.
// Failures degrade to warnings like the other collectors.
func collectAssetInventory(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := cloudasset.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("cloudasset: %v", err)
		return
	}
	scope := "projects/" + rs.ProjectID

	// 1. Resources: asset types whose encryption/CMEK posture we want to check.
	page, err := svc.V1.SearchAllResources(scope).AssetTypes(caiAssetTypes...).Do()
	if err != nil {
		rs.warn("cloudasset search resources: %v", err)
		return
	}
	for _, r := range page.Results {
		switch r.AssetType {
		case "bigquery.googleapis.com/Dataset":
			rs.BigQueryDatasets = append(rs.BigQueryDatasets, r)
		case "run.googleapis.com/Service":
			rs.CloudRunServices = append(rs.CloudRunServices, r)
		case "pubsub.googleapis.com/Topic":
			rs.PubSubTopics = append(rs.PubSubTopics, r)
		}
	}

	// 2. IAM: any policy binding granting public principals across the project.
	iamPage, err := svc.V1.SearchAllIamPolicies(scope).
		Query("policy:allUsers OR policy:allAuthenticatedUsers").Do()
	if err != nil {
		rs.warn("cloudasset search iam: %v", err)
		return
	}
	rs.PublicIAM = iamPage.Results
}

// shortName returns the trailing identifier of a full GCP resource name, e.g.
// "projects/p/datasets/analytics" => "analytics".
func shortName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 && i < len(full)-1 {
		return full[i+1:]
	}
	return full
}

// datasetEncryptionKMS extracts the dataset-level default encryption CMEK key
// name from the versioned bigquery dataset resource, if configured.
func datasetEncryptionKMS(r *cloudasset.ResourceSearchResult) string {
	for _, v := range r.VersionedResources {
		var d struct {
			DefaultEncryptionConfiguration struct {
				KmsKeyName string `json:"kmsKeyName"`
			} `json:"defaultEncryptionConfiguration"`
		}
		if err := json.Unmarshal(v.Resource, &d); err == nil {
			return d.DefaultEncryptionConfiguration.KmsKeyName
		}
	}
	return ""
}

// iamResultHasPublicMember reports whether a CAI IAM search result binds a
// public principal; it also returns the offending member.
func iamResultHasPublicMember(r *cloudasset.IamPolicySearchResult) (string, bool) {
	if r.Policy == nil {
		return "", false
	}
	for _, b := range r.Policy.Bindings {
		if m, ok := hasPublicMember(b.Members); ok {
			return m, true
		}
	}
	return "", false
}
