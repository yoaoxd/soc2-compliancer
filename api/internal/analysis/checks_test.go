package analysis

import (
	"strings"
	"testing"

	"google.golang.org/api/cloudresourcemanager/v3"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/secretmanager/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
)

func bucket(name string, uniform, versioning, cmek bool) *storage.Bucket {
	b := &storage.Bucket{Name: name, Location: "US"}
	if uniform {
		b.IamConfiguration = &storage.BucketIamConfiguration{
			UniformBucketLevelAccess: &storage.BucketIamConfigurationUniformBucketLevelAccess{Enabled: true},
		}
	}
	if versioning {
		b.Versioning = &storage.BucketVersioning{Enabled: true}
	}
	if cmek {
		b.Encryption = &storage.BucketEncryption{DefaultKmsKeyName: "projects/p/locations/global/keyRings/r/cryptoKeys/k"}
	}
	return b
}

func TestBucketUniformAccess(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", Buckets: []*storage.Bucket{bucket("open", false, true, true)}}
	got := checkBucketUniformAccess(rs)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Severity != "high" || got[0].CheckName != "storage_bucket_uniform_access" {
		t.Fatalf("unexpected finding: %+v", got[0])
	}
	if !strings.Contains(got[0].Remediation.TerraformConfig, "uniform_bucket_level_access = true") {
		t.Fatal("remediation config missing uniform access flag")
	}
	if got[0].Remediation.ImportCommand != "terraform import google_storage_bucket.open open" {
		t.Fatalf("unexpected import command: %s", got[0].Remediation.ImportCommand)
	}
}

func TestBucketPublicBinding(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		Buckets:   []*storage.Bucket{bucket("pub", true, true, true)},
		BucketPolicies: map[string][]*storage.PolicyBindings{
			"pub": {{Role: "roles/storage.objectViewer", Members: []string{"allUsers"}}},
		},
	}
	got := checkBucketPublicBinding(rs)
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical finding, got %+v", got)
	}
}

func TestBucketVersioning(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", Buckets: []*storage.Bucket{bucket("novers", true, false, true)}}
	got := checkBucketVersioning(rs)
	if len(got) != 1 || got[0].CheckName != "storage_bucket_versioning" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestBucketCMEK(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", Buckets: []*storage.Bucket{bucket("nokms", true, true, false)}}
	got := checkBucketCMEK(rs)
	if len(got) != 1 || got[0].CheckName != "storage_bucket_cmek" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSQLChecks(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", SQLInstances: []*sqladmin.DatabaseInstance{{
		Name:    "db1",
		Project: "p",
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{SslMode: "ALLOW_UNENCRYPTED_AND_ENCRYPTED"},
		},
	}}}
	if got := checkSQLSsl(rs); len(got) != 1 || got[0].CheckName != "sql_ssl_encrypted_only" {
		t.Fatalf("ssl: unexpected %+v", got)
	}
	if got := checkSQLBackups(rs); len(got) != 1 || got[0].CheckName != "sql_backups_enabled" {
		t.Fatalf("backups: unexpected %+v", got)
	}
	if got := checkSQLHA(rs); len(got) != 1 || got[0].CheckName != "sql_high_availability" {
		t.Fatalf("ha: unexpected %+v", got)
	}
	if got := checkSQLDeletionProtection(rs); len(got) != 1 || got[0].CheckName != "sql_deletion_protection" {
		t.Fatalf("deletion protection: unexpected %+v", got)
	}
}

func TestSQLPublicExposure(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", SQLInstances: []*sqladmin.DatabaseInstance{{
		Name:    "db2",
		Project: "p",
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{Ipv4Enabled: true},
		},
	}}}
	got := checkSQLPublicExposure(rs)
	if len(got) != 1 || got[0].CheckName != "sql_public_exposure" || got[0].Severity != "high" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSQLPITR(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", SQLInstances: []*sqladmin.DatabaseInstance{{
		Name:    "dbp",
		Project: "p",
		Settings: &sqladmin.Settings{
			BackupConfiguration: &sqladmin.BackupConfiguration{Enabled: true},
		},
	}}}
	got := checkSQLPITR(rs)
	if len(got) != 1 || got[0].CheckName != "sql_pitr_enabled" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSQLBroadAuthorizedNetworks(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", SQLInstances: []*sqladmin.DatabaseInstance{{
		Name:    "dbn",
		Project: "p",
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				AuthorizedNetworks: []*sqladmin.AclEntry{{Value: "0.0.0.0/0"}},
			},
		},
	}}}
	got := checkSQLBroadAuthorizedNetworks(rs)
	if len(got) != 1 || got[0].CheckName != "sql_broad_authorized_networks" || got[0].Severity != "critical" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestBucketRetention(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", Buckets: []*storage.Bucket{bucket("ret", true, true, true)}}
	got := checkBucketRetention(rs)
	if len(got) != 1 || got[0].CheckName != "storage_bucket_retention" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSecretRotation(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p", Secrets: []*secretmanager.Secret{
		{Name: "projects/p/secrets/api-key"},
	}}
	got := checkSecretRotation(rs)
	if len(got) != 1 || got[0].CheckName != "secret_rotation_period" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestComputeOSLoginAndSSHKeys(t *testing.T) {
	inst := &compute.Instance{
		Name:     "vm1",
		Zone:     "projects/p/zones/us-central1-a",
		Metadata: &compute.Metadata{Items: []*compute.MetadataItems{{Key: "ssh-keys", Value: strPtr("user:ssh-rsa AAAA...")}}},
	}
	rs := &ResourceSet{ProjectID: "p", ComputeInstances: []*compute.Instance{inst}}
	if got := checkComputeOSLogin(rs); len(got) != 1 || got[0].CheckName != "compute_oslogin" {
		t.Fatalf("oslogin: unexpected %+v", got)
	}
	if got := checkComputeSSHKeysMetadata(rs); len(got) != 1 || got[0].CheckName != "compute_ssh_keys_metadata" || got[0].Severity != "critical" {
		t.Fatalf("sshkeys: unexpected %+v", got)
	}
}

func TestFirewallEgressBroad(t *testing.T) {
	fw := &compute.Firewall{
		Name:              "allow-all-egress",
		Direction:         "EGRESS",
		DestinationRanges: []string{"0.0.0.0/0"},
		Allowed:           []*compute.FirewallAllowed{{IPProtocol: "all"}},
	}
	rs := &ResourceSet{ProjectID: "p", Firewalls: []*compute.Firewall{fw}}
	got := checkFirewallEgressBroad(rs)
	if len(got) != 1 || got[0].CheckName != "firewall_egress_broad" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func strPtr(s string) *string { return &s }

func TestFirewallBroadIngress(t *testing.T) {
	fw := &compute.Firewall{
		Name:         "allow-all-ssh",
		Direction:    "INGRESS",
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
	}
	if ok, proto := isBroadIngress(fw.Allowed[0], fw.SourceRanges); !ok || proto != "tcp" {
		t.Fatal("expected broad ingress detection")
	}
	if ok, _ := isBroadIngress(&compute.FirewallAllowed{IPProtocol: "tcp", Ports: []string{"443"}}, fw.SourceRanges); ok {
		t.Fatal("443 from 0.0.0.0/0 should not be flagged as management ingress")
	}
	if ok, _ := isBroadIngress(&compute.FirewallAllowed{IPProtocol: "tcp", Ports: []string{"22"}}, []string{"10.0.0.0/8"}); ok {
		t.Fatal("ssh from private range should not be flagged")
	}
	if ok, proto := isBroadIngress(&compute.FirewallAllowed{IPProtocol: "all"}, fw.SourceRanges); !ok || proto != "all" {
		t.Fatal("allow-all should be detected as broad ingress")
	}
}

func TestFirewallLogging(t *testing.T) {
	fw := &compute.Firewall{
		Name:         "allow-web",
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80", "443"}}},
	}
	rs := &ResourceSet{ProjectID: "p", Firewalls: []*compute.Firewall{fw}}
	got := checkFirewallLogging(rs)
	if len(got) != 1 || got[0].CheckName != "firewall_logging" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestPrimitiveRoles(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		ProjectIAM: []*cloudresourcemanager.Binding{
			{Role: "roles/owner", Members: []string{"user:admin@example.com"}},
		},
	}
	got := checkProjectPrimitiveRoles(rs)
	if len(got) != 1 || got[0].CheckName != "project_primitive_roles" || got[0].Severity != "high" {
		t.Fatalf("unexpected: %+v", got)
	}
	if got[0].Remediation.ImportCommand != "" || got[0].Remediation.TerraformConfig != "" {
		t.Fatal("IAM removal must not emit a grant or an unreviewed mutation command")
	}
}

func TestProjectPublicBindings(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		ProjectIAM: []*cloudresourcemanager.Binding{
			{Role: "roles/viewer", Members: []string{"allUsers"}},
		},
	}
	got := checkProjectPublicBindings(rs)
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestLoggingAuditSink(t *testing.T) {
	rs := &ResourceSet{ProjectID: "p"} // no sinks
	got := checkLoggingAuditSink(rs)
	if len(got) != 1 || got[0].CheckName != "logging_audit_sink" || got[0].Severity != "high" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSecretPublicBinding(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		SecretPolicies: map[string][]*secretmanager.Binding{
			"projects/p/secrets/api-key": {{Role: "roles/secretmanager.secretAccessor", Members: []string{"allAuthenticatedUsers"}}},
		},
	}
	got := checkSecretPublicBinding(rs)
	if len(got) != 1 || got[0].CheckName != "secret_public_binding" || got[0].Severity != "critical" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSlugFor(t *testing.T) {
	cases := map[string]string{
		"my-bucket":         "my_bucket",
		"MyBucket.Web":      "my_bucket_web",
		"9lives":            "r_9lives",
		"a--b":              "a_b",
		"projects/p/x":      "projects_p_x",
		"_underscore-start": "underscore_start",
	}
	for in, want := range cases {
		if got := slugFor(in); got != want {
			t.Errorf("slugFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEvaluateOrdering(t *testing.T) {
	rs := &ResourceSet{
		ProjectID: "p",
		Buckets:   []*storage.Bucket{bucket("b1", false, false, false)},
		Firewalls: []*compute.Firewall{{
			Name:         "bad",
			Direction:    "INGRESS",
			SourceRanges: []string{"0.0.0.0/0"},
			Allowed:      []*compute.FirewallAllowed{{IPProtocol: "all"}},
		}},
	}
	got := Evaluate(rs)
	if len(got) == 0 {
		t.Fatal("expected findings")
	}
	if got[0].Severity != "critical" {
		t.Fatalf("expected critical first, got %s (%s)", got[0].Severity, got[0].CheckName)
	}
	for i := 1; i < len(got); i++ {
		if sevRank(got[i-1].Severity) > sevRank(got[i].Severity) {
			t.Fatalf("findings not ordered: %s before %s", got[i-1].Severity, got[i].Severity)
		}
	}
}
