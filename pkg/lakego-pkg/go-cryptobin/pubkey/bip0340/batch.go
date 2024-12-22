package bip0340

/*
 * BIP0340 batch verification functions.
 */
func BatchVerify(pub []*PublicKey, m, sig [][]byte, hashFunc Hasher) bool {
    u := len(pub)

    if len(m) == 0 || len(m) < u || len(sig) < u {
        return false
    }

    pub0 := pub[0]

    for i := 1; i < u; i++ {
        if pub[i].Curve != pub0.Curve {
            return false
        }
    }

    for i := 0; i < u; i++ {
        if !VerifyBytes(pub[i], hashFunc, m[i], sig[i]) {
            return false
        }
    }

    return true
}
