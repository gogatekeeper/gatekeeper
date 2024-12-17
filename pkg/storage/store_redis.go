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
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	redis "github.com/redis/go-redis/v9"
)

var _ Storage = (*RedisStore)(nil)

type RedisStore struct {
	Client *redis.Client
}

// newRedisStore creates a new redis store.
func newRedisStore(url string) (Storage, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	return RedisStore{Client: client}, nil
}

// Set adds a token to the store.
func (r RedisStore) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	if err := r.Client.Set(ctx, key, value, expiration); err.Err() != nil {
		return err.Err()
	}

	return nil
}

// Checks if key exists in store.
func (r RedisStore) Exists(ctx context.Context, key string) (bool, error) {
	val, err := r.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return val > 0, nil
}

// Get retrieves a token from the store.
func (r RedisStore) Get(ctx context.Context, key string) (string, error) {
	result := r.Client.Get(ctx, key)
	if result.Err() != nil {
		return "", result.Err()
	}

	return result.Val(), nil
}

// Delete remove the key.
func (r RedisStore) Delete(ctx context.Context, key string) error {
	return r.Client.Del(ctx, key).Err()
}

// Close closes of any open resources.
func (r RedisStore) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}

	return nil
}

// Get retrieves a token from the store, the key we are using here is the access token.
func (r RedisStore) GetRefreshTokenFromStore(
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
