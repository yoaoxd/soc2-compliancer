package encrypt

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// AWSKMSSetup holds the configuration needed to talk to an AWS KMS
// customer-managed key that acts as the envelope KEK.
type AWSKMSSetup struct {
	Region    string // optional if credentials carry a region
	KeyID     string // KMS key ARN or alias, e.g. alias/soc2-master
}

// NewAWSKEK builds a KEK backed by AWS KMS. The KMS client is created from the
// ambient AWS SDK credential chain (env vars, shared config, etc).
func NewAWSKEK(ctx context.Context, setup AWSKMSSetup) (KEK, error) {
	var opts []func(*config.LoadOptions) error
	if setup.Region != "" {
		opts = append(opts, config.WithRegion(setup.Region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := kms.NewFromConfig(cfg)
	return &awsKEK{client: client, keyID: setup.KeyID}, nil
}

type awsKEK struct {
	client *kms.Client
	keyID  string
}

func (k *awsKEK) Kind() string { return "aws-kms" }

func (k *awsKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := k.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(k.keyID),
		Plaintext: dek,
	})
	if err != nil {
		return nil, fmt.Errorf("kms encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

func (k *awsKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	out, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(k.keyID),
		CiphertextBlob: wrapped,
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	return out.Plaintext, nil
}