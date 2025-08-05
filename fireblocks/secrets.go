package fireblocks

import (
	"crypto/rand"
	"encoding/binary"
)

type secrets struct{}

func (s secrets) Seed(seed int64) {}

func (s secrets) Uint64() (r uint64) {
	err := binary.Read(rand.Reader, binary.BigEndian, &r)
	if err != nil {
		panic(err)
	}
	return r
}

func (s secrets) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}
