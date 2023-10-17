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

package proxy

import (
	"context"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"

	"go.uber.org/zap"
)

// useStore checks if we are using a store to hold the refresh tokens
func (r *OauthProxy) useStore() bool {
	return r.Store != nil
}

// StoreRefreshToken the token to the store
func (r *OauthProxy) StoreRefreshToken(ctx context.Context, token string, value string, expiration time.Duration) error {
	return r.Store.Set(ctx, utils.GetHashKey(token), value, expiration)
}

// Get retrieves a token from the store, the key we are using here is the access token
func (r *OauthProxy) GetRefreshToken(ctx context.Context, token string) (string, error) {
	// step: the key is the access token
	val, err := r.Store.Get(ctx, utils.GetHashKey(token))

	if err != nil {
		return val, err
	}
	if val == "" {
		return val, apperrors.ErrNoSessionStateFound
	}

	return val, nil
}

// DeleteRefreshToken removes a key from the store
func (r *OauthProxy) DeleteRefreshToken(ctx context.Context, token string) error {
	if err := r.Store.Delete(ctx, utils.GetHashKey(token)); err != nil {
		r.Log.Error("unable to delete token", zap.Error(err))

		return err
	}

	return nil
}

// Close is used to close off any resources
func (r *OauthProxy) CloseStore() error {
	if r.Store != nil {
		return r.Store.Close()
	}

	return nil
}
