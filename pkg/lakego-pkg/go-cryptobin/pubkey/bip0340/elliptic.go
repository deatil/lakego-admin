package bip0340

var s256 *CurveParams

func init() {
    s256 = &CurveParams{
        Name:    "secp256k1",
        BitSize: 256,
        P:       bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        N:       bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000007"),
        Gx:      bigFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        Gy:      bigFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    }
}

// The following conventions are used, with constants as defined for secp256k1.
// We note that adapting this specification to other elliptic curves is not straightforward
// and can result in an insecure scheme
func S256() *CurveParams {
    return s256
}
