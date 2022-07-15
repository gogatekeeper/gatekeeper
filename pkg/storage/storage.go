package storage

import (
	"fmt"
	"net/url"
	"time"
)

// storage is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie
type Storage interface {
	// Set the token to the store
	Set(string, string, time.Duration) error
	// Get retrieves a token from the store
	Get(string) (string, error)
	// Exists checks if key exists in store
	Exists(string) (bool, error)
	// Delete removes a key from the store
	Delete(string) error
	// Close is used to close off any resources
	Close() error
}

// createStorage creates the store client for use
func CreateStorage(location string) (Storage, error) {
	var store Storage
	var err error

	u, err := url.Parse(location)

	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "redis":
		store, err = newRedisStore(u)
	default:
		return nil, fmt.Errorf("unsupport store: %s", u.Scheme)
	}

	return store, err
}
