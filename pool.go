package secp256k1

import (
	"math/big"
	"sync"
)

type numPool struct {
	bns         []*big.Int
	leakedcount int
	sync.Mutex
}

func (pool *numPool) Get() *big.Int {
	pool.Lock()
	defer pool.Unlock()
	if pool == nil {
		return new(big.Int)
	}

	pool.leakedcount++
	l := len(pool.bns)
	if l == 0 {
		return new(big.Int)
	}

	bn := pool.bns[l-1]
	pool.bns = pool.bns[:l-1]
	return bn
}

func (pool *numPool) Put(bn *big.Int) {
	pool.Lock()
	defer pool.Unlock()
	if pool == nil {
		return
	}
	pool.bns = append(pool.bns, bn)
	pool.leakedcount--
}

func (pool *numPool) Count() int {
	return pool.leakedcount
}
