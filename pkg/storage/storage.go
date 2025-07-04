package storage

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
)

// storage is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie.
type Storage interface {
	// Set the token to the store
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	// Get retrieves a token from the store
	Get(ctx context.Context, key string) (string, error)
	// Exists checks if key exists in store
	Exists(ctx context.Context, key string) (bool, error)
	// Delete removes a key from the store
	Delete(ctx context.Context, key string) error
	// Close is used to close off any resources
	Close() error
	GetRefreshTokenFromStore(ctx context.Context, token string) (string, error)
	Test(ctx context.Context) error
}

// createStorage creates the store client for use.
func CreateStorage(location string, highAvail bool, caPool *x509.CertPool) (Storage, error) {
	uri, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	switch uri.Scheme {
	case constant.RedisScheme:
		builder, err := newRedisStoreBuilder(location, highAvail)
		if err != nil {
			return nil, err
		}

		return builder.Build(), nil
	case constant.TLSRedisScheme:
		builder, err := newRedisStoreBuilder(location, highAvail)
		if err != nil {
			return nil, err
		}

		if caPool != nil {
			builder.WithCACert(caPool)
		}

		return builder.Build(), nil
	default:
		return nil, fmt.Errorf("unsupport store: %s", uri.Scheme)
	}
}
