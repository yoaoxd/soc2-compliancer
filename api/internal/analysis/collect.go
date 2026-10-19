package analysis

import (
	"context"
	"net/http"

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

func collectStorage(ctx context.Context, client *http.Client, rs *ResourceSet) error {
	svc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return err
	}

	var pageToken string
	for {
		req := svc.Buckets.List(rs.ProjectID).MaxResults(1000)
		if pageToken != "" {
			req.PageToken(pageToken)
		}
		list, err := req.Do()
		if err != nil {
			rs.warn("storage: %v", err)
			return nil
		}
		for _, b := range list.Items {
			rs.Buckets = append(rs.Buckets, b)
			if policy, err := svc.Buckets.GetIamPolicy(b.Name).Do(); err == nil {
				rs.BucketPolicies[b.Name] = policy.Bindings
			} else {
				rs.warn("storage iam policy for %s: %v", b.Name, err)
			}
		}
		pageToken = list.NextPageToken
		if pageToken == "" {
			break
		}
	}
	return nil
}

func collectSQL(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := sqladmin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("sqladmin: %v", err)
		return
	}
	list, err := svc.Instances.List(rs.ProjectID).Do()
	if err != nil {
		rs.warn("sqladmin instances: %v", err)
		return
	}
	rs.SQLInstances = list.Items
}

func collectCompute(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("compute: %v", err)
		return
	}

	if agg, err := svc.Instances.AggregatedList(rs.ProjectID).Do(); err == nil {
		for _, scoped := range agg.Items {
			rs.ComputeInstances = append(rs.ComputeInstances, scoped.Instances...)
		}
	} else {
		rs.warn("compute instances: %v", err)
	}

	if fw, err := svc.Firewalls.List(rs.ProjectID).Do(); err == nil {
		rs.Firewalls = fw.Items
	} else {
		rs.warn("compute firewalls: %v", err)
	}

	if sub, err := svc.Subnetworks.AggregatedList(rs.ProjectID).Do(); err == nil {
		for _, scoped := range sub.Items {
			rs.Subnets = append(rs.Subnets, scoped.Subnetworks...)
		}
	} else {
		rs.warn("compute subnetworks: %v", err)
	}

	if tmpl, err := svc.InstanceTemplates.List(rs.ProjectID).Do(); err == nil {
		rs.InstanceTemplates = tmpl.Items
	} else {
		rs.warn("compute instance templates: %v", err)
	}
}

func collectIAM(ctx context.Context, client *http.Client, rs *ResourceSet) {
	iamSvc, err := iam.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("iam: %v", err)
		return
	}
	if list, err := iamSvc.Projects.ServiceAccounts.List("projects/" + rs.ProjectID).Do(); err == nil {
		rs.SAs = list.Accounts
		for _, sa := range rs.SAs {
			if keys, err := iamSvc.Projects.ServiceAccounts.Keys.List(sa.Name).KeyTypes("USER_MANAGED").Do(); err == nil {
				rs.SAKeys[sa.Email] = keys.Keys
			} else if rs.SAKeysWarn == "" {
				rs.SAKeysWarn = "service account keys: " + err.Error()
			}
		}
	} else {
		rs.warn("iam service accounts: %v", err)
	}

	crm, err := cloudresourcemanagerv3.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("cloudresourcemanager: %v", err)
		return
	}
	policy, err := crm.Projects.GetIamPolicy("projects/"+rs.ProjectID,
		&cloudresourcemanagerv3.GetIamPolicyRequest{}).Do()
	if err != nil {
		rs.IAMPolicyWarn = err.Error()
		return
	}
	rs.ProjectIAM = policy.Bindings
}

func collectLogging(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := logging.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("logging: %v", err)
		return
	}
	list, err := svc.Projects.Sinks.List("projects/" + rs.ProjectID).Do()
	if err != nil {
		rs.warn("logging sinks: %v", err)
		return
	}
	rs.Sinks = list.Sinks
}

func collectKMS(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := cloudkms.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("cloudkms: %v", err)
		return
	}
	parent := "projects/" + rs.ProjectID + "/locations/-"
	var ringToken string
	for {
		req := svc.Projects.Locations.KeyRings.List(parent).PageSize(500)
		if ringToken != "" {
			req.PageToken(ringToken)
		}
		rings, err := req.Do()
		if err != nil {
			rs.warn("cloudkms keyrings: %v", err)
			return
		}
		for _, ring := range rings.KeyRings {
			var keyToken string
			for {
				keyReq := svc.Projects.Locations.KeyRings.CryptoKeys.List(ring.Name).PageSize(500)
				if keyToken != "" {
					keyReq.PageToken(keyToken)
				}
				keys, err := keyReq.Do()
				if err != nil {
					rs.warn("cloudkms keys in %s: %v", ring.Name, err)
					break
				}
				rs.CryptoKeys = append(rs.CryptoKeys, keys.CryptoKeys...)
				keyToken = keys.NextPageToken
				if keyToken == "" {
					break
				}
			}
		}
		ringToken = rings.NextPageToken
		if ringToken == "" {
			break
		}
	}
}

func collectSecrets(ctx context.Context, client *http.Client, rs *ResourceSet) {
	svc, err := secretmanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		rs.warn("secretmanager: %v", err)
		return
	}
	var token string
	for {
		req := svc.Projects.Secrets.List("projects/" + rs.ProjectID)
		if token != "" {
			req.PageToken(token)
		}
		list, err := req.Do()
		if err != nil {
			rs.warn("secretmanager secrets: %v", err)
			return
		}
		for _, s := range list.Secrets {
			rs.Secrets = append(rs.Secrets, s)
			if policy, err := svc.Projects.Secrets.GetIamPolicy(s.Name).Do(); err == nil {
				rs.SecretPolicies[s.Name] = policy.Bindings
			} else {
				rs.warn("secretmanager iam for %s: %v", s.Name, err)
			}
		}
		token = list.NextPageToken
		if token == "" {
			break
		}
	}
}
