package xmss

import (
    "bytes"
    "crypto/subtle"
)

const (
    XMSS_HASH_PADDING_F = 0
    XMSS_HASH_PADDING_H = 1
    XMSS_HASH_PADDING_HASH = 2
    XMSS_HASH_PADDING_PRF  = 3
    XMSS_HASH_PADDING_PRF_KEYGEN = 4
)

// coreHash
func coreHash(params *Params, in []byte) []byte {
    h := params.Hash()
    h.Write(in)
    res := h.Sum(nil)

    if params.n == 24 && len(res) >= 24 {
        res = res[:24]
    } else if params.n == 32 && len(res) >= 32 {
        res = res[:32]
    } else if params.n == 64 && len(res) >= 64 {
        res = res[:64]
    }

    return res
}

// PRF: SHA2-256(toBytes(3, 32) || KEY || M)
// Message must be exactly 32 bytes
func hashPRF(params *Params, out, key, m []byte) {
    var buf bytes.Buffer
    buf.Write(toBytes(XMSS_HASH_PADDING_PRF, params.paddingLen))
    buf.Write(key[:params.n])
    buf.Write(m)

    res := coreHash(params, buf.Bytes())

    copy(out, res)
}

// hashKeygen
func hashKeygen(params *Params, out, key, m []byte) {
    var buf bytes.Buffer
    buf.Write(toBytes(XMSS_HASH_PADDING_PRF_KEYGEN, params.paddingLen))
    buf.Write(key[:params.n])
    buf.Write(m)

    res := coreHash(params, buf.Bytes())

    copy(out, res)
}

// H_msg: SHA2-256(toBytes(2, 32) || KEY || M)
// Computes the message hash using R, the public root, the index of the leaf
// node, and the message.
func hashMsg(params *Params, out, R, root, mPlus []byte, idx uint64) {
    copy(mPlus[:params.paddingLen], toBytes(XMSS_HASH_PADDING_HASH, params.paddingLen))
    copy(mPlus[params.paddingLen:params.paddingLen+params.n], R[:params.n])
    copy(mPlus[params.paddingLen+params.n:params.paddingLen+2*params.n], root[:params.n])
    copy(mPlus[params.paddingLen+2*params.n:params.paddingLen+3*params.n], toBytes(int(idx), params.n))

    var buf bytes.Buffer
    buf.Write(mPlus)

    res := coreHash(params, buf.Bytes())

    copy(out, res)
}

// H: SHA2-256(toBytes(1, 32) || KEY || M)
// A cryptographic hash function H.  H accepts n-byte keys and byte
// strings of length 2n and returns an n-byte string.
// Includes: Algorithm 7: RAND_HASH
func hashH(params *Params, out, seed, m []byte, a *address) {
    var data bytes.Buffer
    data.Write(toBytes(XMSS_HASH_PADDING_H, params.paddingLen))

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

    subtle.XORBytes(buf[params.n:], m, bitmask)
    data.Write(buf)

    res := coreHash(params, data.Bytes())

    copy(out, res)
}

// F: SHA2-256(toBytes(0, 32) || KEY || M)
func hashF(params *Params, out, seed, m []byte, a *address) {
    var data bytes.Buffer
    data.Write(toBytes(XMSS_HASH_PADDING_F, params.paddingLen))

    // Generate the n-byte key
    a.setKeyAndMask(0)
    buf := make([]byte, 2*params.n)
    hashPRF(params, buf[:params.n], seed, a.toBytes())

    // Generate the n-byte mask
    a.setKeyAndMask(1)
    bitmask := make([]byte, params.n)
    hashPRF(params, bitmask, seed, a.toBytes())

    subtle.XORBytes(buf[params.n:], m, bitmask)
    data.Write(buf)

    res := coreHash(params, data.Bytes())

    copy(out, res)
}
