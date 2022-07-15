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
	"net/url"
	"time"

	redis "gopkg.in/redis.v4"
)

var _ Storage = (*RedisStore)(nil)

type RedisStore struct {
	Client *redis.Client
}

// newRedisStore creates a new redis store
func newRedisStore(location *url.URL) (Storage, error) {
	// step: get any password
	password := ""
	if location.User != nil {
		password, _ = location.User.Password()
	}

	// step: parse the url notation
	client := redis.NewClient(&redis.Options{
		Addr:     location.Host,
		DB:       0,
		Password: password,
	})

	return RedisStore{
		Client: client,
	}, nil
}

// Set adds a token to the store
func (r RedisStore) Set(key, value string, expiration time.Duration) error {
	if err := r.Client.Set(key, value, expiration); err.Err() != nil {
		return err.Err()
	}

	return nil
}

// Checks if key exists in store
func (r RedisStore) Exists(key string) (bool, error) {
	result := r.Client.Exists(key)
	if result.Err() != nil {
		return false, result.Err()
	}

	return result.Val(), nil
}

// Get retrieves a token from the store
func (r RedisStore) Get(key string) (string, error) {
	result := r.Client.Get(key)
	if result.Err() != nil {
		return "", result.Err()
	}

	return result.Val(), nil
}

// Delete remove the key
func (r RedisStore) Delete(key string) error {
	return r.Client.Del(key).Err()
}

// Close closes of any open resources
func (r RedisStore) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}

	return nil
}
