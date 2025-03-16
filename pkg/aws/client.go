package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

// NewACMClient creates a new AWS ACM client using default configuration
func NewACMClient(ctx context.Context) (*acm.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := acm.NewFromConfig(cfg)
	return client, nil
}

// NewACMClientWithRegion creates a new AWS ACM client for the specified region
// If region is empty, it uses the default region from the environment
func NewACMClientWithRegion(ctx context.Context, region string) (*acm.Client, error) {
	opts := []func(*config.LoadOptions) error{}
	
	// If a specific region is requested, use it
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	client := acm.NewFromConfig(cfg)
	return client, nil
}