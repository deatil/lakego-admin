package hash

import (
    "github.com/spaolacci/murmur3"
)

// murmur32
func Murmur32(data string) uint32 {
    return murmur3.Sum32([]byte(data))
}

// murmur32
func Murmur32WithSeed(data string, seed uint32) uint32 {
    return murmur3.Sum32WithSeed([]byte(data), seed)
}

// ================

// murmur64
func Murmur64(data string) uint64 {
    return murmur3.Sum64([]byte(data))
}

// murmur64
func Murmur64WithSeed(data string, seed uint32) uint64 {
    return murmur3.Sum64WithSeed([]byte(data), seed)
}

// ================

// murmur128
func Murmur128(data string) (uint64, uint64) {
    return murmur3.Sum128([]byte(data))
}

// murmur128
func Murmur128WithSeed(data string, seed uint32) (uint64, uint64) {
    return murmur3.Sum128WithSeed([]byte(data), seed)
}
