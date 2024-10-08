package nums

import (
    "sync"
    "math/big"
    "crypto/elliptic"
)

// see http://www.watersprings.org/pub/id/draft-black-numscurves-01.html

var (
    once sync.Once

    p256d1, p384d1, p512d1 *elliptic.CurveParams
    p256t1, p384t1, p512t1 *rcurve
)

func initAll() {
    initP256d1()
    initP256t1()

    initP384d1()
    initP384t1()

    initP512d1()
    initP512t1()
}

func initP256d1() {
    p256d1 = &elliptic.CurveParams{
        P: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"),
        N: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE43C8275EA265C6020AB20294751A825"),
        B: bigFromHex("25581"),
        Gx: bigFromHex("01"),
        Gy: bigFromHex("696F1853C1E466D7FC82C96CCEEEDD6BD02C2F9375894EC10BF46306C2B56C77"),
        BitSize: 256,
        Name: "numsp256d1",
    }
}

func initP256t1() {
    twisted := p256d1
    params := &elliptic.CurveParams{
        Name:    "numsp256t1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("0D")
    params.Gy = bigFromHex("7D0AB41E2A1276DBA3D330B39FA046BFBE2A6D63824D303F707F6FB5331CADBA")
    r := bigFromHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE6AA55AD0A6BC64E5B84E6F1122B4AD")
    p256t1 = newRcurve(twisted, params, r)
}

func initP384d1() {
    p384d1 = &elliptic.CurveParams{
        P: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC3"),
        N: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD61EAF1EEB5D6881BEDA9D3D4C37E27A604D81F67B0E61B9"),
        B: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77BB"),
        Gx: bigFromHex("02"),
        Gy: bigFromHex("3C9F82CB4B87B4DC71E763E0663E5DBD8034ED422F04F82673330DC58D15FFA2B4A3D0BAD5D30F865BCBBF503EA66F43"),
        BitSize: 384,
        Name: "numsp384d1",
    }
}

func initP384t1() {
    twisted := p384d1
    params := &elliptic.CurveParams{
        Name:    "numsp384t1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("08")
    params.Gy = bigFromHex("749CDABA136CE9B65BD4471794AA619DAA5C7B4C930BFF8EBD798A8AE753C6D72F003860FEBABAD534A4ACF5FA7F5BEE")
    r := bigFromHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFECD7D11ED5A259A25A13A0458E39F4E451D6D71F70426E25")
    p384t1 = newRcurve(twisted, params, r)
}

func initP512d1() {
    p512d1 = &elliptic.CurveParams{
        P: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
        N: bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5B3CA4FB94E7831B4FC258ED97D0BDC63B568B36607CD243CE153F390433555D"),
        B: bigFromHex("1D99B"),
        Gx: bigFromHex("02"),
        Gy: bigFromHex("1C282EB23327F9711952C250EA61AD53FCC13031CF6DD336E0B9328433AFBDD8CC5A1C1F0C716FDC724DDE537C2B0ADB00BB3D08DC83755B205CC30D7F83CF28"),
        BitSize: 512,
        Name: "numsp512d1",
    }
}

func initP512t1() {
    twisted := p512d1
    params := &elliptic.CurveParams{
        Name:    "numsp512t1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("20")
    params.Gy = bigFromHex("7D67E841DC4C467B605091D80869212F9CEB124BF726973F9FF048779E1D614E62AE2ECE5057B5DAD96B7A897C1D72799261134638750F4F0CB91027543B1C5E")
    r := bigFromHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA7E50809EFDABBB9A624784F449545F0DCEA5FF0CB800F894E78D1CB0B5F0189")
    p512t1 = newRcurve(twisted, params, r)
}

func bigFromHex(s string) (i *big.Int) {
    i = new(big.Int)
    i.SetString(s, 16)

    return
}
