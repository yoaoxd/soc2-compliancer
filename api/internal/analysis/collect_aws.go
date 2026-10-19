package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// awsClient returns a typed S3 client configured with the static credentials.
func awsClient(ctx context.Context, creds *AWSCredentials) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(creds.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
		)),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load aws config: %w", err)
	}
	return cfg, nil
}

// Collector is the entry point for collecting AWS resources.
func CollectAWS(ctx context.Context, creds *AWSCredentials) (*ResourceSet, error) {
	cfg, err := awsClient(ctx, creds)
	if err != nil {
		return nil, err
	}
	rs := &ResourceSet{
		AccountID: creds.Region + "-aws",
		AWSBuckets:   []AWSBucket{},
		AWSRDS:       []AWSRDSInstance{},
		AWSEC2:       []AWSEC2Instance{},
		AWSSecurityGroups: []AWSSecurityGroup{},
		AWSKMS:       []AWSKMSKey{},
		AWSIAMUsers:  []AWSIAMUser{},
	} // AccountID set after IAM identity resolution if possible
	rs.Warnings = []string{}

	collectAWSBuckets(ctx, cfg, rs)
	collectAWSRDS(ctx, cfg, rs)
	collectAWSEC2(ctx, cfg, rs)
	collectAWSKMS(ctx, cfg, rs)
	collectAWSIAM(ctx, cfg, rs)
	collectAWSCloudTrail(ctx, cfg, rs)
	return rs, nil
}

func collectAWSBuckets(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := s3.NewFromConfig(cfg)
	list, err := svc.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		rs.warn("aws s3 list buckets: %v", err)
		return
	}
	for _, b := range list.Buckets {
		name := aws.ToString(b.Name)
		bucket := AWSBucket{Name: name}

		if poc, err := svc.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name}); err == nil {
			p := poc.PublicAccessBlockConfiguration
			bucket.PublicBlock = p != nil &&
				aws.ToBool(p.BlockPublicAcls) && aws.ToBool(p.BlockPublicPolicy) &&
				aws.ToBool(p.IgnorePublicAcls) && aws.ToBool(p.RestrictPublicBuckets)
		}

		if enc, err := svc.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name}); err == nil {
			if len(enc.ServerSideEncryptionConfiguration.Rules) > 0 {
				rule := enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
				if rule != nil {
					algo := string(rule.SSEAlgorithm)
					bucket.Encrypted = true
					if (algo == "aws:kms" || algo == "aws:kms:dsse") && aws.ToString(rule.KMSMasterKeyID) != "" {
						bucket.CMEK = true
					}
				}
			}
		}

		if ver, err := svc.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: b.Name}); err == nil {
			bucket.Versioning = ver.Status == s3types.BucketVersioningStatusEnabled		}

		if pol, err := svc.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: b.Name}); err == nil {
			if pol.PolicyStatus != nil {
				if aws.ToBool(pol.PolicyStatus.IsPublic) {
					bucket.PublicPolicy = "bucket policy is public"
				}
			}
		}

		rs.AWSBuckets = append(rs.AWSBuckets, bucket)
	}
}

func collectAWSRDS(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := rds.NewFromConfig(cfg)
	out, err := svc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		rs.warn("aws rds describe: %v", err)
		return
	}
	for _, d := range out.DBInstances {
		rs.AWSRDS = append(rs.AWSRDS, AWSRDSInstance{
			Identifier:         aws.ToString(d.DBInstanceIdentifier),
			Engine:             aws.ToString(d.Engine),
			StorageEncrypted:   aws.ToBool(d.StorageEncrypted),
			DeletionProtection: aws.ToBool(d.DeletionProtection),
			MultiAZ:            aws.ToBool(d.MultiAZ),
			BackupRetention:    *d.BackupRetentionPeriod,
			PubliclyAccessible: aws.ToBool(d.PubliclyAccessible),
			Region:             aws.ToString(d.AvailabilityZone),
		})
	}
	// mark region on the resource set if not known
	if len(rs.AWSRDS) > 0 && strings.Contains(rs.AccountID, "-aws") {
		// availability zones encode region; keep simple
	}
}

func collectAWSEC2(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := ec2.NewFromConfig(cfg)
	out, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		rs.warn("aws ec2 instances: %v", err)
		return
	}
	for _, res := range out.Reservations {
		for _, inst := range res.Instances {
			name := ""
			for _, t := range inst.Tags {
				if aws.ToString(t.Key) == "Name" {
					name = aws.ToString(t.Value)
				}
			}
			publicIP := false
			for _, ni := range inst.NetworkInterfaces {
				if ni.Association != nil && aws.ToString(ni.Association.PublicIp) != "" {
					publicIP = true
				}
			}
			if inst.PublicIpAddress != nil && aws.ToString(inst.PublicIpAddress) != "" {
				publicIP = true
			}
			rs.AWSEC2 = append(rs.AWSEC2, AWSEC2Instance{
				InstanceID: aws.ToString(inst.InstanceId),
				Name:       name,
				PublicIP:   publicIP,
				Region:     credsRegionFromZone(aws.ToString(inst.Placement.AvailabilityZone)),
			})
		}
	}

	// Security groups: capture ingress rules.
	sgOut, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err == nil {
		for _, sg := range sgOut.SecurityGroups {
			group := AWSSecurityGroup{
				GroupID: aws.ToString(sg.GroupId),
				Name:    aws.ToString(sg.GroupName),
				Egress0: false,
			}
			for _, rule := range sg.IpPermissions {
				ing := AWSIngressRule{
					FromPort:    portOf(rule.FromPort),
					ToPort:      portOf(rule.ToPort),
					AllProtocol: rule.IpProtocol != nil && strings.EqualFold(aws.ToString(rule.IpProtocol), "-1"),
					Cidr0:       cidrIs0(rule.IpRanges) || cidrIs0v6(rule.Ipv6Ranges),
				}
				group.Ingress = append(group.Ingress, ing)
			}
			if eg, err := svc.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
				Filters: []ec2types.Filter{{Name: aws.String("group-id"), Values: []string{aws.ToString(sg.GroupId)}},
					{Name: aws.String("is-egress"), Values: []string{"true"}}},
			}); err == nil {
				for _, r := range eg.SecurityGroupRules {
					if r.IsEgress != nil && *r.IsEgress && aws.ToString(r.CidrIpv4) == "0.0.0.0/0" && aws.ToString(r.IpProtocol) == "-1" {
						group.Egress0 = true
					}
				}
			}
			rs.AWSSecurityGroups = append(rs.AWSSecurityGroups, group)
		}
	} else {
		rs.warn("aws security groups: %v", err)
	}
}

func portOf(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func cidrIs0(ranges []ec2types.IpRange) bool {
	for _, r := range ranges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func cidrIs0v6(ranges []ec2types.Ipv6Range) bool {
	for _, r := range ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func credsRegionFromZone(az string) string {
	if strings.HasSuffix(az, "") || az == "" {
		return ""
	}
	return az[:len(az)-1]
}

func collectAWSKMS(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := kms.NewFromConfig(cfg)
	out, err := svc.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		rs.warn("aws kms list: %v", err)
		return
	}
	for _, k := range out.Keys {
		keyID := aws.ToString(k.KeyId)
		key := AWSKMSKey{KeyID: keyID, KeyARN: aws.ToString(k.KeyArn)}
		if d, err := svc.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId}); err == nil && d.KeyMetadata != nil {
			key.Manager = string(d.KeyMetadata.KeyManager)
		}
		if rot, err := svc.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId}); err == nil {
			key.RotationEnabled = rot.KeyRotationEnabled
		}
		rs.AWSKMS = append(rs.AWSKMS, key)
	}
}

func collectAWSIAM(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := iam.NewFromConfig(cfg)
	out, err := svc.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		rs.warn("aws iam users: %v", err)
		return
	}
	for _, u := range out.Users {
		keys, err := svc.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
		var count int32
		if err == nil {
			count = int32(len(keys.AccessKeyMetadata))
		}
		rs.AWSIAMUsers = append(rs.AWSIAMUsers, AWSIAMUser{
			UserName:   aws.ToString(u.UserName),
			AccessKeys: count,
		})
	}
}

func collectAWSCloudTrail(ctx context.Context, cfg aws.Config, rs *ResourceSet) {
	svc := cloudtrail.NewFromConfig(cfg)
	out, err := svc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		rs.warn("aws cloudtrail: %v", err)
		return
	}
	for _, t := range out.TrailList {
		rs.AWSCloudTrails = append(rs.AWSCloudTrails, AWSCloudTrail{
			Name:        aws.ToString(t.Name),
			MultiRegion: aws.ToBool(t.IsMultiRegionTrail),
			HasBucket:   aws.ToString(t.S3BucketName) != "",
		})
	}
	if len(rs.AWSCloudTrails) == 0 {
		rs.warn("aws cloudtrail: no trails found")
	}
}