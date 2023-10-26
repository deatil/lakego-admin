package curve256k1

import (
    "bytes"
    "testing"
)

func TestScalarMult1(t *testing.T) {
    var q PointJacobian
    q.x.Set(hex2element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    q.y.Set(hex2element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
    k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")

    q.ScalarMult(&q, k)

    var p Point
    p.FromJacobian(&q)

    wantX := decodeHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    wantY := decodeHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    if x := p.x.Bytes(); !bytes.Equal(x, wantX) {
        t.Errorf("want %x, got %x", wantX, x)
    }
    if y := p.y.Bytes(); !bytes.Equal(y, wantY) {
        t.Errorf("want %x, got %x", wantY, y)
    }
}

func TestScalarMultMinus1(t *testing.T) {
    var q PointJacobian
    q.x.Set(hex2element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    q.y.Set(hex2element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
    k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")

    q.ScalarMult(&q, k)

    var p Point
    p.FromJacobian(&q)

    wantX := decodeHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    wantY := decodeHex("b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777")
    if x := p.x.Bytes(); !bytes.Equal(x, wantX) {
        t.Errorf("want %x, got %x", wantX, x)
    }
    if y := p.y.Bytes(); !bytes.Equal(y, wantY) {
        t.Errorf("want %x, got %x", wantY, y)
    }
}

func TestScalarBaseMult1(t *testing.T) {
    var q PointJacobian
    k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")
    q.ScalarBaseMult(k)

    var p Point
    p.FromJacobian(&q)

    wantX := decodeHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    wantY := decodeHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    if x := p.x.Bytes(); !bytes.Equal(x, wantX) {
        t.Errorf("want %x, got %x", wantX, x)
    }
    if y := p.y.Bytes(); !bytes.Equal(y, wantY) {
        t.Errorf("want %x, got %x", wantY, y)
    }
}

func TestScalarBaseMultMinus1(t *testing.T) {
    var q PointJacobian
    k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
    q.ScalarBaseMult(k)

    var p Point
    p.FromJacobian(&q)

    wantX := decodeHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    wantY := decodeHex("b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777")
    if x := p.x.Bytes(); !bytes.Equal(x, wantX) {
        t.Errorf("want %x, got %x", wantX, x)
    }
    if y := p.y.Bytes(); !bytes.Equal(y, wantY) {
        t.Errorf("want %x, got %x", wantY, y)
    }
}

func BenchmarkScalarMult1(b *testing.B) {
    var q PointJacobian
    q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
    q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
    q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
    k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        q.ScalarMult(&q, k)
    }
}

func BenchmarkScalarMultMinus1(b *testing.B) {
    var q PointJacobian
    q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
    q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
    q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
    k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        q.ScalarMult(&q, k)
    }
}
