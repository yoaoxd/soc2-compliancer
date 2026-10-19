package analysis

import (
	"testing"

	cloudasset "google.golang.org/api/cloudasset/v1"
	compute "google.golang.org/api/compute/v1"
)

func caiResource(assetType, name string, kmsKeys ...string) *cloudasset.ResourceSearchResult {
	return &cloudasset.ResourceSearchResult{
		AssetType: assetType,
		Name:      name,
		Location:  "us-central1",
		KmsKeys:   kmsKeys,
	}
}

func publicIAM(assetType, resource string) *cloudasset.IamPolicySearchResult {
	return &cloudasset.IamPolicySearchResult{
		AssetType: assetType,
		Resource:  resource,
		Policy: &cloudasset.Policy{
			Bindings: []*cloudasset.Binding{
				{Role: "roles/bigquery.dataViewer", Members: []string{"allUsers"}},
			},
		},
	}
}

func TestBigQueryDatasetPublicBinding(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		PublicIAM: []*cloudasset.IamPolicySearchResult{
			publicIAM("bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/p/datasets/analytics"),
		},
	}
	got := checkBigQueryDatasetPublicBinding(rs)
	if len(got) != 1 || got[0].CheckName != "bigquery_dataset_public_binding" || got[0].Severity != "critical" {
		t.Fatalf("unexpected: %+v", got)
	}
	if got[0].ResourceName != "analytics" {
		t.Fatalf("expected short resource name, got %q", got[0].ResourceName)
	}
	if got[0].Remediation.ImportCommand == "" {
		t.Fatal("expected remediation import command")
	}
}

func TestBigQueryDatasetCMEK(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		BigQueryDatasets: []*cloudasset.ResourceSearchResult{
			caiResource("bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/p/datasets/no-kms"),
			caiResource("bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/p/datasets/with-kms", "projects/p/locations/global/keyRings/r/cryptoKeys/k"),
		},
	}
	got := checkBigQueryDatasetCMEK(rs)
	if len(got) != 1 || got[0].CheckName != "bigquery_dataset_cmek" || got[0].ResourceName != "no-kms" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestBigQueryDatasetCMEKFromVersionedResource(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		BigQueryDatasets: []*cloudasset.ResourceSearchResult{{
			AssetType: "bigquery.googleapis.com/Dataset",
			Name:      "//bigquery.googleapis.com/projects/p/datasets/v-kms",
			VersionedResources: []*cloudasset.VersionedResource{{
				Resource: []byte(`{"defaultEncryptionConfiguration":{"kmsKeyName":"projects/p/locations/global/keyRings/r/cryptoKeys/k"}}`),
			}},
		}},
	}
	got := checkBigQueryDatasetCMEK(rs)
	if len(got) != 0 {
		t.Fatalf("expected CMEK to be detected from versioned resource, got %+v", got)
	}
}

func TestCloudRunPublicInvoker(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		PublicIAM: []*cloudasset.IamPolicySearchResult{
			publicIAM("run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/api"),
		},
	}
	got := checkCloudRunPublicInvoker(rs)
	if len(got) != 1 || got[0].CheckName != "cloud_run_public_invoker" || got[0].Severity != "critical" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestCloudRunCMEK(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		CloudRunServices: []*cloudasset.ResourceSearchResult{
			caiResource("run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/plain"),
			caiResource("run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/encrypted", "projects/p/locations/global/keyRings/r/cryptoKeys/k"),
		},
	}
	got := checkCloudRunCMEK(rs)
	if len(got) != 1 || got[0].CheckName != "cloud_run_cmek" || got[0].ResourceName != "plain" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestPubSubTopicCMEK(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		PubSubTopics: []*cloudasset.ResourceSearchResult{
			caiResource("pubsub.googleapis.com/Topic", "//pubsub.googleapis.com/projects/p/topics/events"),
		},
	}
	got := checkPubSubTopicCMEK(rs)
	if len(got) != 1 || got[0].CheckName != "pubsub_topic_cmek" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestInstanceTemplateShielded(t *testing.T) {
	plain := &compute.InstanceTemplate{
		Name:       "tpl-plain",
		Properties: &compute.InstanceProperties{},
	}
	shielded := &compute.InstanceTemplate{
		Name: "tpl-shielded",
		Properties: &compute.InstanceProperties{
			ShieldedInstanceConfig: &compute.ShieldedInstanceConfig{
				EnableSecureBoot:          true,
				EnableVtpm:                true,
				EnableIntegrityMonitoring: true,
			},
		},
	}
	rs := &ResourceSet{
		ProjectID:         "p",
		InstanceTemplates: []*compute.InstanceTemplate{plain, shielded},
	}
	got := checkInstanceTemplateShielded(rs)
	if len(got) != 1 || got[0].CheckName != "instance_template_shielded" || got[0].ResourceName != "tpl-plain" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestCAIChecksRegisteredInEvaluate(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		PublicIAM: []*cloudasset.IamPolicySearchResult{
			publicIAM("bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/p/datasets/pub"),
			publicIAM("run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/api"),
		},
		BigQueryDatasets:  []*cloudasset.ResourceSearchResult{caiResource("bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/p/datasets/nokms")},
		CloudRunServices:  []*cloudasset.ResourceSearchResult{caiResource("run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/plain")},
		PubSubTopics:      []*cloudasset.ResourceSearchResult{caiResource("pubsub.googleapis.com/Topic", "//pubsub.googleapis.com/projects/p/topics/events")},
		InstanceTemplates: []*compute.InstanceTemplate{{Name: "t", Properties: &compute.InstanceProperties{}}},
	}
	got := Evaluate(rs)
	var seen []string
	for _, f := range got {
		seen = append(seen, f.CheckName)
	}
	for _, want := range []string{
		"bigquery_dataset_public_binding", "bigquery_dataset_cmek",
		"cloud_run_public_invoker", "cloud_run_cmek",
		"pubsub_topic_cmek", "instance_template_shielded",
	} {
		found := false
		for _, s := range seen {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %q in Evaluate output, got %v", want, seen)
		}
	}
}
