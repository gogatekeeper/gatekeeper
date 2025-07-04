/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package storage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	redis "github.com/redis/go-redis/v9"
)

type BasicRedis interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Exists(ctx context.Context, key ...string) *redis.IntCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, key ...string) *redis.IntCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

var (
	_ Storage = (*RedisStore[*redis.Client])(nil)
	_ Storage = (*RedisStore[*redis.ClusterClient])(nil)
)

type RedisStore[T BasicRedis] struct {
	Client BasicRedis
}

type RedisStoreBuilder struct {
	opts          *redis.Options
	clusteredOpts *redis.ClusterOptions
}

func newRedisStoreBuilder(url string, clustered bool) (*RedisStoreBuilder, error) {
	if clustered {
		opts, err := redis.ParseClusterURL(url)
		if err != nil {
			return nil, err
		}

		return &RedisStoreBuilder{clusteredOpts: opts}, nil
	}

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	return &RedisStoreBuilder{opts: opts}, nil
}

func (b *RedisStoreBuilder) WithCACert(caPool *x509.CertPool) *RedisStoreBuilder {
	if b.clusteredOpts != nil {
		if b.clusteredOpts.TLSConfig == nil {
			b.clusteredOpts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}

		b.clusteredOpts.TLSConfig.RootCAs = caPool

		return b
	}

	if b.opts.TLSConfig == nil {
		b.opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	b.opts.TLSConfig.RootCAs = caPool

	return b
}

func (b *RedisStoreBuilder) WithClientCert(tlsCert *tls.Certificate) *RedisStoreBuilder {
	if b.clusteredOpts != nil {
		if b.clusteredOpts.TLSConfig == nil {
			b.clusteredOpts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}

		b.clusteredOpts.TLSConfig.Certificates = []tls.Certificate{*tlsCert}

		return b
	}

	if b.opts.TLSConfig == nil {
		b.opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	b.opts.TLSConfig.Certificates = []tls.Certificate{*tlsCert}

	return b
}

func (b *RedisStoreBuilder) Build() Storage {
	if b.clusteredOpts != nil {
		return &RedisStore[*redis.ClusterClient]{redis.NewClusterClient(b.clusteredOpts)}
	}
	return &RedisStore[*redis.Client]{redis.NewClient(b.opts)}
}

// Set adds a token to the store.
func (r *RedisStore[T]) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	if err := r.Client.Set(ctx, key, value, expiration); err.Err() != nil {
		return err.Err()
	}

	return nil
}

// Checks if key exists in store.
func (r *RedisStore[T]) Exists(ctx context.Context, key string) (bool, error) {
	val, err := r.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return val > 0, nil
}

// Get retrieves a token from the store.
func (r *RedisStore[T]) Get(ctx context.Context, key string) (string, error) {
	result := r.Client.Get(ctx, key)
	if result.Err() != nil {
		return "", result.Err()
	}

	return result.Val(), nil
}

// Delete remove the key.
func (r *RedisStore[T]) Delete(ctx context.Context, key string) error {
	return r.Client.Del(ctx, key).Err()
}

// Close closes of any open resources.
func (r *RedisStore[T]) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}

	return nil
}

// Test connection to store.
func (r *RedisStore[T]) Test(ctx context.Context) error {
	result := r.Client.Ping(ctx)

	if result.Err() != nil {
		return errors.Join(apperrors.ErrRedisConnection, result.Err())
	}

	if result.Val() != "PONG" {
		return apperrors.ErrConnectionTestFailed
	}

	return nil
}

// Get retrieves a token from the store, the key we are using here is the access token.
func (r *RedisStore[T]) GetRefreshTokenFromStore(
	ctx context.Context,
	token string,
) (string, error) {
	// step: the key is the access token
	val, err := r.Get(ctx, utils.GetHashKey(token))
	if err != nil {
		return val, err
	}
	if val == "" {
		return val, apperrors.ErrNoSessionStateFound
	}

	return val, nil
}
