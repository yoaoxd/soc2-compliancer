package analysis

import "fmt"

// AWSCredentials is the subset of AWS temporary/static credentials the analyzer
// needs. Access keys are short-lived where possible (STS assume-role), but the
// HTTP API also accepts static keys.
type AWSCredentials struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

func (c *AWSCredentials) Valid() error {
	if c.Region == "" {
		return fmt.Errorf("aws credentials missing region")
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return fmt.Errorf("aws credentials missing access_key_id/secret_access_key")
	}
	return nil
}

// AWS resources captured by the collector (analysis-friendly subset).
type AWSBucket struct {
	Name           string
	Versioning     bool
	Encrypted      bool // SSE (AES256 or aws:kms) configured
	CMEK           bool // SSE-KMS with a customer-managed key
	PublicBlock    bool // PublicAccessBlockConfiguration blocks all public access
	PublicPolicy   string
	AccountID      string
}

type AWSRDSInstance struct {
	Identifier       string
	Engine           string
	StorageEncrypted bool
	DeletionProtection bool
	MultiAZ          bool
	BackupRetention  int32
	PubliclyAccessible bool
	Region           string
}

type AWSEC2Instance struct {
	InstanceID string
	Name       string
	PublicIP   bool // has a public IP address assigned
	Region     string
}

type AWSSecurityGroup struct {
	GroupID  string
	Name     string
	Egress0  bool // allows all egress to 0.0.0.0/0
	Ingress  []AWSIngressRule
}

type AWSIngressRule struct {
	FromPort    int32
	ToPort      int32
	AllProtocol bool
	Cidr0       bool // 0.0.0.0/0 or ::/0
}

type AWSKMSKey struct {
	KeyID         string
	KeyARN        string
	RotationEnabled bool
	Manager       string // "CUSTOMER" | "AWS"
}

type AWSIAMUser struct {
	UserName   string
	AccessKeys int32
}

type AWSCloudTrail struct {
	Name     string
	MultiRegion bool
	HasBucket bool // bucket name configured
}