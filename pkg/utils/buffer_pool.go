package utils

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
)

type LimitedBufferPool struct {
	pool  *sync.Pool
	limit int32
	count int32
}

func NewLimitedBufferPool(limit int32) *LimitedBufferPool {
	return &LimitedBufferPool{
		pool: &sync.Pool{
			New: func() any {
				return &bytes.Buffer{}
			},
		},
		limit: limit,
		count: 0,
	}
}

func (limPool *LimitedBufferPool) Get() (*bytes.Buffer, error) {
	curr := atomic.LoadInt32(&limPool.count)
	if curr > 0 {
		atomic.AddInt32(&limPool.count, int32(-1))
	}

	val, ok := limPool.pool.Get().(*bytes.Buffer)
	if !ok {
		return nil, errors.New("assertion to *bytes.Buffer failed")
	}

	return val, nil
}

func (limPool *LimitedBufferPool) Put(buf *bytes.Buffer) {
	curr := atomic.LoadInt32(&limPool.count)
	if curr <= limPool.limit {
		atomic.AddInt32(&limPool.count, int32(1))

		buf.Reset()
		limPool.pool.Put(buf)
	}
}

func (limPool *LimitedBufferPool) Capacity() int32 {
	return atomic.LoadInt32(&limPool.count)
}
