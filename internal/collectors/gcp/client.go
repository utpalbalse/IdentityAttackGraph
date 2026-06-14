// Package gcp collects service accounts, keys, IAM bindings, and impersonation/federation trust
// from a single GCP project. It authenticates via Application Default Credentials / Workload
// Identity Federation (no stored static keys), and is read-only. See docs/GCP_COLLECTOR.md.
package gcp

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iam "google.golang.org/api/iam/v1"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
)

// Options configures a GCP collector for one project.
type Options struct {
	ProjectID string
	// CredentialsFile is an optional path to a service-account or WIF credentials file. If empty,
	// Application Default Credentials are used (env, gcloud, metadata server, or WIF).
	CredentialsFile string
	// AuditLookbackHours bounds the first (cursorless) Cloud Audit Log pull.
	AuditLookbackHours int
}

// clients bundles the Google API services a collection pass needs.
type clients struct {
	iam     *iam.Service
	crm     *cloudresourcemanager.Service
	logging *logging.Service
}

func newClients(ctx context.Context, opts Options) (*clients, error) {
	var o []option.ClientOption
	if opts.CredentialsFile != "" {
		o = append(o, option.WithCredentialsFile(opts.CredentialsFile))
	}
	iamSvc, err := iam.NewService(ctx, o...)
	if err != nil {
		return nil, fmt.Errorf("iam service (check ADC/WIF credentials): %w", err)
	}
	crmSvc, err := cloudresourcemanager.NewService(ctx, o...)
	if err != nil {
		return nil, fmt.Errorf("resource manager service: %w", err)
	}
	logSvc, err := logging.NewService(ctx, o...)
	if err != nil {
		return nil, fmt.Errorf("logging service: %w", err)
	}
	return &clients{iam: iamSvc, crm: crmSvc, logging: logSvc}, nil
}
