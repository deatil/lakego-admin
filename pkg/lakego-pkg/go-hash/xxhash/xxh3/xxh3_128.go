package xxh3

import(
    "fmt"
)

// New128 returns a new Hash128 computing the XXH3-128 checksum
func New128() Hash128 {
    return New128WithSeed(0)
}

// New128WithSecret returns a new Hash128 computing the XXH3-128 checksum
func New128WithSecret(secret []byte) (Hash128, error) {
    if len(secret) < SECRET_SIZE_MIN {
        return nil, fmt.Errorf("secret too short")
    }

    return newDigest128(0, secret), nil
}

// New128WithSeed returns a new Hash128 computing the XXH3-128 checksum
func New128WithSeed(seed uint64) Hash128 {
    secret := make([]byte, SECRET_DEFAULT_SIZE)
    GenCustomSecret(secret, seed)

    return newDigest128(seed, secret)
}

// Sum128 returns the 128bits Hash value.
func Sum128(input []byte) (out [Size128]byte) {
    d := New128()
    d.Write(input)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum128WithSeed returns the 128bits Hash value.
func Sum128WithSeed(input []byte, seed uint64) (out [Size128]byte) {
    d := New128WithSeed(seed)
    d.Write(input)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// Checksum128 returns the Uint128 value.
func Checksum128(input []byte) Uint128 {
    d := New128()
    d.Write(input)

    return d.Sum128()
}

// Checksum128WithSeed returns the Uint128 value.
func Checksum128WithSeed(input []byte, seed uint64) Uint128 {
    d := New128WithSeed(seed)
    d.Write(input)

    return d.Sum128()
}
