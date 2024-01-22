package field

import (
    "fmt"
    "testing"
    "math/big"
)

func Test_Bytes(t *testing.T) {
    var d Element

    d.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01})

    bs := d.Bytes()

    check := "08"
    got := fmt.Sprintf("%x", bs)

    if got != check {
        t.Errorf("Bytes error, got %s, want %s", got, check)
    }
}

func Test_SetBytes(t *testing.T) {
    var el Element
    var d *big.Int

    d, _ = new(big.Int).SetString("08", 16)

    el.SetBytes(d.Bytes())

    check2 := [9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01}
    check := fmt.Sprintf("%x", check2)
    got := fmt.Sprintf("%x", el.l)

    if got != check {
        t.Errorf("SetBytes error, got %s, want %s", got, check)
    }
}

func Test_ToBig(t *testing.T) {
    var d Element

    d.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01})

    big := d.ToBig()

    check := "08"
    got := fmt.Sprintf("%x", big.Bytes())

    if got != check {
        t.Errorf("ToBig error, got %s, want %s", got, check)
    }
}

func Test_FromBig(t *testing.T) {
    var el Element
    var d *big.Int

    d, _ = new(big.Int).SetString("08", 16)

    el.FromBig(d)

    check2 := [9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01}
    check := fmt.Sprintf("%x", check2)
    got := fmt.Sprintf("%x", el.l)

    if got != check {
        t.Errorf("FromBig error, got %s, want %s", got, check)
    }
}

func Test_Dup(t *testing.T) {
    var d, d2 Element

    d.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01})

    d2.Dup(&d)

    check := fmt.Sprintf("%x", d.l)
    got := fmt.Sprintf("%x", d2.l)

    if got != check {
        t.Errorf("Dup error, got %s, want %s", got, check)
    }
}

func Test_ReduceDegree(t *testing.T) {
    var d LargeElement
    var d2 Element

    d = LargeElement([17]uint64{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01, 0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x01})

    d2.reduceDegree(&d)

    check := "[18 0 ffff800 2000 0 0 10000000 0 0]"
    got := fmt.Sprintf("%x", d2.l)

    if got != check {
        t.Errorf("ReduceDegree error, got %s, want %s", got, check)
    }
}

func Test_Reduce(t *testing.T) {
    var d Element

    d.reduce(3)

    check := "[6 0 1ffffd00 17ff 0 0 0 6000000 0]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("Reduce error, got %s, want %s", got, check)
    }
}

func Test_Square(t *testing.T) {
    var d, d2 Element

    d.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01})

    d2.Square(&d)

    check := "[80 0 1fffc000 1ffff 0 0 0 0 8]"
    got := fmt.Sprintf("%x", d2.l)

    if got != check {
        t.Errorf("Square error, got %s, want %s", got, check)
    }
}

func Test_Mul(t *testing.T) {
    var a, b Element
    var d Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    b.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    d.Mul(&a, &b)

    check := "[1c09409a 76bffff 49fc00a b02028e 1000007d ffffd3a 5ed7 ffc1310 1f6c07]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("Mul error, got %s, want %s", got, check)
    }
}

func Test_Sub(t *testing.T) {
    var a, b Element
    var d Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    b.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    d.Sub(&a, &b)

    check := "[1fffffff fffffff 200000fe ffff7ff 1fffffff fffffda 1fffffff e000011 1fffffff]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("Sub error, got %s, want %s", got, check)
    }
}

func Test_Add(t *testing.T) {
    var a, b Element
    var d Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    b.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    d.Add(&a, &b)

    check := "[21 0 1ffff001 7fff 0 25 0 12 2]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("Add error, got %s, want %s", got, check)
    }
}

func Test_Scalar(t *testing.T) {
    var d Element

    d.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})

    d.Scalar(3)

    check := "[33 0 1fffe800 bfff 0 0 0 36 3]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("Scalar error, got %s, want %s", got, check)
    }
}

func Test_CopyConditional(t *testing.T) {
    var a, d Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})

    d.CopyConditional(&a, 3)

    check := "[1 0 0 3 0 0 0 2 1]"
    got := fmt.Sprintf("%x", d.l)

    if got != check {
        t.Errorf("CopyConditional error, got %s, want %s", got, check)
    }
}

func Test_Equal(t *testing.T) {
    var a, b Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    b.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})

    eq := a.Equal(&b)
    if eq != 1 {
        t.Errorf("Equal fail, got %d", eq)
    }
}

func Test_IsZero(t *testing.T) {
    var a Element

    a.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})

    res := a.IsZero()
    if res == 1 {
        t.Errorf("IsZero fail, got %d", res)
    }
}

func Test_IsZero2(t *testing.T) {
    var a Element

    res := a.IsZero()
    if res != 1 {
        t.Errorf("IsZero2 fail, got %d", res)
    }
}
