package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ACMClientOptions holds configuration options for creating an ACM client
type ACMClientOptions struct {
	Region  string
	RoleARN string
}

// NewACMClient creates a new AWS ACM client using default configuration
func NewACMClient(ctx context.Context) (*acm.Client, error) {
	return NewACMClientWithOptions(ctx, ACMClientOptions{})
}

// NewACMClientWithRegion creates a new AWS ACM client for the specified region
// If region is empty, it uses the default region from the environment
func NewACMClientWithRegion(ctx context.Context, region string) (*acm.Client, error) {
	return NewACMClientWithOptions(ctx, ACMClientOptions{
		Region: region,
	})
}

// NewACMClientWithOptions creates a new AWS ACM client with the specified options
func NewACMClientWithOptions(ctx context.Context, options ACMClientOptions) (*acm.Client, error) {
	opts := []func(*config.LoadOptions) error{}
	
	// If a specific region is requested, use it
	if options.Region != "" {
		opts = append(opts, config.WithRegion(options.Region))
	}
	
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	// If a role ARN is provided, configure AssumeRole credentials
	if options.RoleARN != "" {
		// Create an STS client to assume the role
		stsClient := sts.NewFromConfig(cfg)
		
		// Configure the assume role credentials provider
		// Default session duration is 15 minutes (900 seconds)
		provider := stscreds.NewAssumeRoleProvider(stsClient, options.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.Duration = 15 * time.Minute
		})
		
		// Create a new config with the assumed role credentials
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	// Create and return the ACM client
	client := acm.NewFromConfig(cfg)
	return client, nil
}