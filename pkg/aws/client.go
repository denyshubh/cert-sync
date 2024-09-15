package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

// NewACMClient initializers a new ACM Client

func NewACMClient(ctx context.Context) (*acm.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	return acm.NewFromConfig(cfg), nil
}
