package blake3

import (
    "hash"
    "errors"
)

// New returns a new hash.Hash computing the blake3 checksum.
func New() hash.Hash {
    return NewWithSize(Size)
}

// New returns a new hash.Hash computing the blake3 checksum.
func NewWithSize(size int) hash.Hash {
    return newDigest(iv, 0, size)
}

// NewWithKeyed is like New but initializes key with the given 32-byte slice.
func NewWithKeyed(key []byte) (hash.Hash, error) {
    return NewWithKeyedAndSize(key, Size)
}

// NewWithKeyedAndSize is like New but initializes key with the given 32-byte slice.
func NewWithKeyedAndSize(key []byte, size int) (hash.Hash, error) {
    if len(key) != BLAKE3_KEY_LEN {
        return nil, errors.New("go-hash/blake3: key size errof")
    }

    keyWords := bytesToUint32s(key)

    var keys [8]uint32
    copy(keys[:], keyWords)

    return newDigest(keys, KEYED_HASH, size), nil
}

// NewWithDeriveKey is like New but initializes context
func NewWithDeriveKey(context []byte) hash.Hash {
    return NewWithDeriveKeyAndSize(context, Size)
}

// NewWithDeriveKeyAndSize is like New but initializes context
func NewWithDeriveKeyAndSize(context []byte, size int) hash.Hash {
    hasher := newDigest(iv, DERIVE_KEY_CONTEXT, Size)
    hasher.Write(context)
    contextKey := hasher.Sum(nil)

    contextKeyWords := bytesToUint32s(contextKey)

    var keys [8]uint32
    copy(keys[:], contextKeyWords)

    return newDigest(keys, DERIVE_KEY_MATERIAL, size)
}

// Sum returns the blake3 checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    d := New()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// SumWithKeyed returns the blake3 checksum of the data.
func SumWithKeyed(data []byte, key []byte) (out [Size]byte, err error) {
    d, err := NewWithKeyed(key)
    if err != nil {
        return
    }

    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// SumWithDeriveKey returns the blake3 checksum of the data.
func SumWithDeriveKey(data []byte, context []byte) (out [Size]byte) {
    d := NewWithDeriveKey(context)
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}
