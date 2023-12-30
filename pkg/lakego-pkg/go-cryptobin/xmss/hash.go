package xmss

import (
    "hash"
)

const (
    XMSS_HASH_PADDING_F = 0
    XMSS_HASH_PADDING_H = 1
    XMSS_HASH_PADDING_HASH = 2
    XMSS_HASH_PADDING_PRF = 3
    XMSS_HASH_PADDING_PRF_KEYGEN = 4
)

// coreHash
func coreHash(params *Params) hash.Hash {
    h := params.Hash()

    return h
}

// PRF: SHA2-256(toBytes(3, 32) || KEY || M)
// Message must be exactly 32 bytes
func hashPRF(params *Params, out, key, m []byte) {
    h := coreHash(params)
    h.Write(toBytes(XMSS_HASH_PADDING_PRF, params.paddingLen))
    h.Write(key[:params.n])
    h.Write(m)
    copy(out, h.Sum(nil))
}

// hashKeygen
func hashKeygen(params *Params, out, key, m []byte) {
    h := coreHash(params)
    h.Write(toBytes(XMSS_HASH_PADDING_PRF_KEYGEN, params.paddingLen))
    h.Write(key[:params.n])
    h.Write(m)
    copy(out, h.Sum(nil))
}

// H_msg: SHA2-256(toBytes(2, 32) || KEY || M)
// Computes the message hash using R, the public root, the index of the leaf
// node, and the message.
func hashMsg(params *Params, out, R, root, mPlus []byte, idx uint64) {
    h := coreHash(params)
    copy(mPlus[:params.n], toBytes(XMSS_HASH_PADDING_HASH, params.paddingLen))
    copy(mPlus[params.n:2*params.n], R[:params.n])
    copy(mPlus[2*params.n:3*params.n], root[:params.n])
    copy(mPlus[3*params.n:4*params.n], toBytes(int(idx), params.n))
    h.Write(mPlus)
    copy(out, h.Sum(nil))
}

// H: SHA2-256(toBytes(1, 32) || KEY || M)
// A cryptographic hash function H.  H accepts n-byte keys and byte
// strings of length 2n and returns an n-byte string.
// Includes: Algorithm 7: RAND_HASH
func hashH(params *Params, out, seed, m []byte, a *address) {
    h := coreHash(params)
    h.Write(toBytes(XMSS_HASH_PADDING_H, params.paddingLen))

    // Generate the n-byte key
    a.setKeyAndMask(0)
    buf := make([]byte, 3*params.n)
    hashPRF(params, buf[:params.n], seed, a.toBytes())

    // Generate the 2n-byte mask
    a.setKeyAndMask(1)
    bitmask := make([]byte, 2*params.n)
    hashPRF(params, bitmask[:params.n], seed, a.toBytes())

    a.setKeyAndMask(2)
    hashPRF(params, bitmask[params.n:], seed, a.toBytes())

    xor(buf[params.n:], m, bitmask)
    h.Write(buf)

    copy(out, h.Sum(nil))
}

// F: SHA2-256(toBytes(0, 32) || KEY || M)
func hashF(params *Params, out, seed, m []byte, a *address) {
    h := coreHash(params)
    h.Write(toBytes(XMSS_HASH_PADDING_F, params.paddingLen))

    // Generate the n-byte key
    a.setKeyAndMask(0)
    buf := make([]byte, 2*params.n)
    hashPRF(params, buf[:params.n], seed, a.toBytes())

    // Generate the n-byte mask
    a.setKeyAndMask(1)
    bitmask := make([]byte, params.n)
    hashPRF(params, bitmask, seed, a.toBytes())
    xor(buf[params.n:], m, bitmask)
    h.Write(buf)

    copy(out, h.Sum(nil))
}
