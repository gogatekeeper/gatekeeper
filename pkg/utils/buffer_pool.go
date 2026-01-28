package utils

import (
	"bytes"
	"errors"
	"sync"
)

type LimitedBufferPool struct {
	pool  *sync.Pool
	limit uint
	count uint
}

func NewLimitedBufferPool(limit uint) *LimitedBufferPool {
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
	if limPool.count > 0 {
		limPool.count--
	}

	val, ok := limPool.pool.Get().(*bytes.Buffer)
	if !ok {
		return nil, errors.New("assertion to *bytes.Buffer failed")
	}

	return val, nil
}

func (limPool *LimitedBufferPool) Put(buf *bytes.Buffer) {
	if limPool.count <= limPool.limit {
		limPool.count++

		buf.Reset()
		limPool.pool.Put(buf)
	}
}

func (limPool *LimitedBufferPool) Capacity() uint {
	return limPool.count
}
