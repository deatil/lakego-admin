package xmss

// Expands an n-byte array into a len*n byte array using the `prf` function
func expandSeed(params *Params, inseed []byte) (expanded []byte) {
    expanded = make([]byte, params.wotsSignLen)

    ctr := make([]byte, 32)
    var idx int
    for i := 0; i < int(params.wlen); i++ {
        ctr = toBytes(i, 32)
        idx = i * params.n
        hashKeygen(params, expanded[idx:idx+params.n], inseed, ctr)
    }

    return
}

// Section 2.6 Strings of Base w Numbers
// Algorithm 1: base_w
func basew(params *Params, x, output []byte) {
    in := 0
    out := 0
    total := uint(0)
    bits := uint(0)

    for i := 0; i < len(output); i++ {
        if bits == 0 {
            total = uint(x[in])
            in++
            bits += 8
        }

        bits -= params.log2w
        output[out] = uint8(total>>bits) & (uint8(params.w) - 1)
        out++
    }
}

// Section 3.1.2. Algorithm 2: chain - Chaining Function
// out and in have to be n-byte arrays, a is the address of the chain
func chain(params *Params, out, in, seed []byte, start, steps uint32, a *address) {
    copy(out, in)

    for i := start; i < (start + steps); i++ {
        a.setHashAddr(i)
        hashF(params, out, seed, out, a)
    }
}

// Takes a message and derives the matching chain lengths.
// Computes the WOTS+ checksum over a message (in base_w)
// lengths is a wlen-byte array (e.g. 67)
func wotsChecksum(params *Params, lengths, in []byte) {
    basew(params, in, lengths[:params.len1])

    var csum uint16
    for i := 0; i < int(params.len1); i++ {
        csum += uint16(params.w) - 1 - uint16(lengths[i])
    }

    csum <<= 4
    csumBytes := toBytes(int(csum), int(params.len2*uint32(params.log2w)+7)/8)
    basew(params, csumBytes, lengths[params.len1:])
}

type privateWOTS []byte
type publicWOTS []byte
type signatureWOTS []byte

// Section 3.1.3. Algorithm 3: WOTS_genSK - Generating a WOTS+ Private Key
func generatePrivate(params *Params, seed []byte) *privateWOTS {
    var prv privateWOTS
    prv = expandSeed(params, seed)
    return &prv
}

// Section 3.1.4. Algorithm 4: WOTS_genPK - Generating a WOTS+ Public Key From a Private Key
// WOTS key generation. Takes a 32 byte seed for the private key, expands it to
// a full WOTS private key and computes the corresponding public key.
// It requires the seed pubSeed (used to generate bitmasks and hash keys)
// and the address of this WOTS key pair.
func (prv privateWOTS) generatePublic(params *Params, pubSeed []byte, a *address) *publicWOTS {
    var pub publicWOTS
    // prv is wotsSignLen(wlen*n)-byte array
    pub = make([]byte, len(prv))

    for i := uint32(0); i < params.wlen; i++ {
        a.setChainAddr(i)
        idx := int(i) * params.n
        chain(params, pub[idx:idx+params.n], prv[idx:idx+params.n], pubSeed, 0, uint32(params.w)-1, a)
    }

    return &pub
}

// Section 3.1.5. Algorithm 5: WOTS_sign - Generating a signature from a private key and a message
// Takes a n-byte message and the 32-byte seed for the private key to compute a
// signature that is placed at 'sig'.
func (prv privateWOTS) sign(params *Params, in, pubSeed []byte, a *address) *signatureWOTS {
    lengths := make([]byte, params.wlen)
    wotsChecksum(params, lengths, in)

    var sign signatureWOTS
    sign = make([]byte, len(prv))
    copy(sign, prv)

    for i := uint32(0); i < params.wlen; i++ {
        a.setChainAddr(i)
        idx := int(i) * params.n
        chain(params, sign[idx:idx+params.n], sign[idx:idx+params.n], pubSeed, 0, uint32(lengths[i]), a)
    }

    return &sign
}

// Section 3.1.6. Algorithm 6: WOTS_pkFromSig - Computing a WOTS+ public key from a message and its signature
// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
func (sign signatureWOTS) getPublic(params *Params, in, pubSeed []byte, a *address) *publicWOTS {
    lengths := make([]byte, params.wlen)
    wotsChecksum(params, lengths, in)

    var pub publicWOTS
    pub = make([]byte, params.wotsSignLen)

    for i := uint32(0); i < params.wlen; i++ {
        a.setChainAddr(i)
        idx := int(i) * params.n
        chain(params, pub[idx:idx+params.n], sign[idx:idx+params.n], pubSeed, uint32(lengths[i]), uint32(params.w)-1-uint32(lengths[i]), a)
    }

    return &pub
}
