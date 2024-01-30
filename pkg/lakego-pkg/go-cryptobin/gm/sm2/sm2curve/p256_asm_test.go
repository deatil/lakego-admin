//go:build (amd64 && !purego) || (arm64 && !purego)
// +build amd64,!purego arm64,!purego

package curve

import (
    "io"
    "time"
    "testing"
    "math/big"
    "crypto/rand"
    "encoding/hex"
)

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out *p256Element, big *big.Int) {
    for i := range out {
        out[i] = 0
    }

    for i, v := range big.Bits() {
        out[i] = uint64(v)
    }
}

func toBigInt(in *p256Element) *big.Int {
    var valBytes [32]byte
    p256LittleToBig(&valBytes, in)
    return new(big.Int).SetBytes(valBytes[:])
}

func p256MulTest(t *testing.T, x, y, p, r *big.Int) {
    x1 := new(big.Int).Mul(x, r)
    x1 = x1.Mod(x1, p)
    y1 := new(big.Int).Mul(y, r)
    y1 = y1.Mod(y1, p)
    ax := new(p256Element)
    ay := new(p256Element)
    res := new(p256Element)
    res2 := new(p256Element)
    fromBig(ax, x1)
    fromBig(ay, y1)
    p256Mul(res2, ax, ay)
    p256FromMont(res, res2)
    resInt := toBigInt(res)

    expected := new(big.Int).Mul(x, y)
    expected = expected.Mod(expected, p)
    if resInt.Cmp(expected) != 0 {
        t.FailNow()
    }
}

func TestP256MulPMinus1(t *testing.T) {
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
    p256MulTest(t, pMinus1, pMinus1, p, r)
}

func TestFuzzyP256Mul(t *testing.T) {
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    var scalar1 [32]byte
    var scalar2 [32]byte
    var timeout *time.Timer

    if testing.Short() {
        timeout = time.NewTimer(10 * time.Millisecond)
    } else {
        timeout = time.NewTimer(2 * time.Second)
    }
    for {
        select {
        case <-timeout.C:
            return
        default:
        }
        io.ReadFull(rand.Reader, scalar1[:])
        io.ReadFull(rand.Reader, scalar2[:])
        x := new(big.Int).SetBytes(scalar1[:])
        y := new(big.Int).SetBytes(scalar2[:])
        p256MulTest(t, x, y, p, r)
    }
}

func p256SqrTest(t *testing.T, x, p, r *big.Int) {
    x1 := new(big.Int).Mul(x, r)
    x1 = x1.Mod(x1, p)
    ax := new(p256Element)
    res := new(p256Element)
    res2 := new(p256Element)
    fromBig(ax, x1)
    p256Sqr(res2, ax, 1)
    p256FromMont(res, res2)
    resInt := toBigInt(res)

    expected := new(big.Int).Mul(x, x)
    expected = expected.Mod(expected, p)
    if resInt.Cmp(expected) != 0 {
        t.FailNow()
    }
}

func TestP256SqrPMinus1(t *testing.T) {
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
    p256SqrTest(t, pMinus1, p, r)
}

func TestFuzzyP256Sqr(t *testing.T) {
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    var scalar1 [32]byte
    var timeout *time.Timer

    if testing.Short() {
        timeout = time.NewTimer(10 * time.Millisecond)
    } else {
        timeout = time.NewTimer(2 * time.Second)
    }
    for {
        select {
        case <-timeout.C:
            return
        default:
        }
        io.ReadFull(rand.Reader, scalar1[:])
        x := new(big.Int).SetBytes(scalar1[:])
        p256SqrTest(t, x, p, r)
    }
}

func BenchmarkP256Sqr(b *testing.B) {
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    var scalar1 [32]byte
    io.ReadFull(rand.Reader, scalar1[:])
    x := new(big.Int).SetBytes(scalar1[:])
    x1 := new(big.Int).Mul(x, r)
    x1 = x1.Mod(x1, p)
    ax := new(p256Element)
    res := new(p256Element)
    fromBig(ax, x1)
    for i := 0; i < b.N; i++ {
        p256Sqr(res, ax, 20)
    }
}

func Test_p256Inverse(t *testing.T) {
    r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
    p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    gx := &p256Element{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
    res := new(p256Element)
    p256Inverse(res, gx)
    resInt := toBigInt(res)
    xInv := new(big.Int).ModInverse(x, p)
    xInv = new(big.Int).Mul(xInv, r)
    xInv = new(big.Int).Mod(xInv, p)
    if resInt.Cmp(xInv) != 0 {
        t.Errorf("expected %v, got %v", hex.EncodeToString(xInv.Bytes()), hex.EncodeToString(resInt.Bytes()))
    }
}

func BenchmarkP256SelectAffine(b *testing.B) {
    var t0 p256AffinePoint
    for i := 0; i < b.N; i++ {
        p256SelectAffine(&t0, &p256Precomputed[20], 20)
    }
}
