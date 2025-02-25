package nums

import (
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test")
    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

type testData struct {
    name  string
    curve elliptic.Curve
}

func Test_Curve(t *testing.T) {
    tests := []testData{
        {"P256d1", P256d1()},
        {"P384d1", P384d1()},
        {"P512d1", P512d1()},

        {"P256t1", P256t1()},
        {"P384t1", P384t1()},
        {"P512t1", P512t1()},
    }

    for _, c := range tests {
        t.Run(c.name, func(t *testing.T) {
            testCurve(t, c.curve)
        })
    }
}

// ==========

func get_paddQ(x1, y1, x2, y2, a, p *big.Int) (*big.Int, *big.Int) {
    var member, denomintor, tmp big.Int
    var flag bool

    zero := new(big.Int).SetInt64(0)
    two := new(big.Int).SetInt64(2)
    three := new(big.Int).SetInt64(3)

    flag = true

    if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
        member.Mul(three, x1)
        member.Mul(&member, x1)
        member.Add(&member, a)

        denomintor.Mul(two, y1)
    } else {
        member.Sub(y2, y1)
        denomintor.Sub(x2, x1)

        tmp.Mul(&member, &denomintor)
        if tmp.Cmp(zero) == -1 {
            flag = false

            member.Abs(&member)
            denomintor.Abs(&denomintor)
        }
    }

    var gcd big.Int
    gcd.GCD(nil, nil, &member, &denomintor)

    var inverse_deno big.Int
    inverse_deno.ModInverse(&denomintor, p)

    var k big.Int
    k.Mul(&member, &inverse_deno)

    if !flag {
        k.Neg(&k)
    }

    k.Mod(&k, p)

    var x3, y3 big.Int
    x3.Mul(&x3, &k)
    x3.Mul(&x3, &k)
    x3.Sub(&x3, x1)
    x3.Sub(&x3, x2)
    x3.Mod(&x3, p)

    y3.Sub(x1, &x3)
    y3.Mul(&y3, &k)
    y3.Sub(&y3, y1)
    y3.Mod(&y3, p)

    return &x3, &y3
}

func get_order(x0, y0, a, b, p *big.Int) (r *big.Int) {
    var x1, y1 big.Int
    var temp_x, temp_y big.Int
    var n big.Int

    one := new(big.Int).SetInt64(1)

    x1.Set(x0)
    y1.Set(one)
    y1.Neg(&y1)
    y1.Mul(&y1, y0)
    y1.Mod(&y1, p)

    temp_x.Set(x0)
    temp_y.Set(y0)

    n.Set(one)

    var xp, yp *big.Int
    for {
        n.Add(&n, one)
        xp, yp = get_paddQ(&temp_x, &temp_y, x0, y0, a, p)

        if xp.Cmp(&x1) == 0 && yp.Cmp(&y1) == 0 {
            r = n.Add(&n, one)
            return
        }

        temp_x.Set(xp)
        temp_y.Set(yp)
    }

    return
}

func test_GetN(t *testing.T) {
    x0 := bigFromHex("02")
    y0 := bigFromHex("3c9f82cb4b87b4dc71e763e0663e5dbd8034ed422f04f82673330dc58d15ffa2b4a3d0bad5d30f865bcbbf503ea66f43")
    p := bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3")
    a := bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC0")
    b := bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff77bb")

    n := get_order(x0, y0, a, b, p)
    t.Errorf("%x", n.Bytes())
}
