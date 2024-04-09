package chaskey

import (
    "hash"
)

/*

http://mouha.be/chaskey/

https://eprint.iacr.org/2014/386.pdf
https://eprint.iacr.org/2015/1182.pdf

*/

// New returns a new hash.Hash computing the chaskey checksum
// New returns a new 8-round chaskey hasher.
func New(key []byte) (hash.Hash, error) {
    return newDigest(key, 8)
}

// New12 returns a new 12-round chaskey hasher.
func New12(key []byte) (hash.Hash, error) {
    return newDigest(key, 12)
}
