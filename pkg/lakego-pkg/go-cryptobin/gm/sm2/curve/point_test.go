package curve

import (
    "fmt"
    "testing"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

func Test_Point_Double(t *testing.T) {
    var x, y, z field.Element
    var a, d PointJacobian

    x.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x
    a.y = y
    a.z = z

    d.Double(&a)

    check := "[28539f6 480c986 3956df0f eec9da4 10a7cd6e 6fc5aca 1ef3f483 9fb1357 166e5941]-[f36a9a3 49f6e1f 34a85f34 42aec23 5c75e3c ecee859 9889385 d3e762b 7f37739]-[f3aafe 62bad2 39af811f 3f804 17ffffe1 c00068e 1fffe18a e0173a9 1ff08a0f]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("Double error, got %s, want %s", got, check)
    }
}

func Test_Point_Sub(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b, d PointJacobian

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetUint32([9]uint32{0x11, 0x5, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x1, 0x25, 0x0, 0x0, 0x01})
    z2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x26, 0x0, 0x1, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    d.Sub(&a, &b)

    check := "[7c79d5e b2cebe4 3fcb3a58 9fb8149 ca0925a 1370f2e 1d3782b6 a413dbc 1b365c9e]-[39c7db9 b192e51 32f4df6b 6fba0a1 149fdc8e c27aec8 178161b5 1394cad1 1ff4b97]-[1eed1580 ec33d29 8841379 e0c97b4 99a4e26 13ef464 aa9f17f 4090ae6 9f4f6c7]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("Sub error, got %s, want %s", got, check)
    }
}

func Test_Point_Add(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b, d PointJacobian

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetUint32([9]uint32{0x11, 0x5, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x1, 0x25, 0x0, 0x0, 0x01})
    z2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x26, 0x0, 0x1, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    d.Add(&a, &b)

    check := "[e8e7e15 4802be 2ea6312a bbaee69 1cf9c9c0 549e989 2d6aa88 14bf7968 84eba2e]-[1f0581d8 cc489e5 26ca46e3 2e8de30 369cdb0 6fcfc7c 1ecfbcfd 1718f01f 130bb60e]-[1eed1580 ec33d29 8841379 e0c97b4 99a4e26 13ef464 aa9f17f 4090ae6 9f4f6c7]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("Add error, got %s, want %s", got, check)
    }
}

func Test_Point_ToBig(t *testing.T) {
    var x1, y1, z1 field.Element
    var a PointJacobian
    var aa Point

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    x, y := new(big.Int), new(big.Int)
    aa.FromJacobian(&a).ToBig(x, y)

    check := "48b773fa77f8e7d6a9054eeaee6589dd52da31505670892b1967759dae416baa-1f6df16f8e02de4874bcd0009b33c01e530ed7b5f10cf9af3c190a9d2f9891fe"
    got := fmt.Sprintf("%x-%x", x.Bytes(), y.Bytes())

    if got != check {
        t.Errorf("ToBig error, got %s, want %s", got, check)
    }
}

func Test_Point_AddMixed(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2 field.Element
    var a, d PointJacobian
    var b Point

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetUint32([9]uint32{0x15, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetUint32([9]uint32{0x16, 0x1, 0x1F2FF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2

    d.AddMixed(&a, &b)

    check := "[118223c6 bb43dba 37321575 4b83290 19b36445 79dea39 1177ee7e f379494 1ce683bb]-[2bae4a8 5ac3899 28d13848 a0cda5c 8dbcb6d 3d4550e d9e1b36 ff44dd8 90fb76a]-[1d5838b1 d8645d6 1f8d9eff 80ede5a 18c9344d c5efdef b6a0193 c783f09 a8b587]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("AddMixed error, got %s, want %s", got, check)
    }
}

func Test_Point_ScalarBaseMult(t *testing.T) {
    var d PointJacobian
    var scalar [32]uint8

    scalar = [32]uint8{
        1, 2, 3, 4, 5, 6, 7, 8,
        21, 22, 23, 24, 25, 26, 27, 28,
        31, 32, 33, 34, 35, 36, 37, 38,
        11, 12, 13, 14, 15, 16, 17, 18,
    }

    d.ScalarBaseMult(scalar[:])

    check := "[1137b5be f409beb 36820290 25ae555 1521a9bf f8635fa b1abc0b 1463bd2f f8ddaa2]-[2046271 a6f14e0 359702ec fe8db14 1e943f2e a7b047 13c08ebb 12ea1751 19955282]-[6d27b9f f13529c 42e89b5 6736455 1ed4df5f b4d368b 167d68f8 88c31dc 1a84e9b7]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("ScalarBaseMult error, got %s, want %s", got, check)
    }
}

func Test_Point_ScalarMult(t *testing.T) {
    var x1, y1 field.Element
    var d, ad PointJacobian
    var a Point
    var scalar []int8

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.NewPoint(x1.ToBig(), y1.ToBig())

    scalar = []int8{
        1, 2, 3, 4, 5, 6, 7, 8,
        3, 4, 5, 6, 11, 12, 13, 14,
        1, 2, 3, 4, 5, 6, 7, 8,
        11, 12, 13, 14, 15, 6, 7, 8,
    }

    ad.FromAffine(&a)

    d.ScalarMult(&ad, scalar)

    check := "[1a3bf5b1 a7a1528 3fa9c542 8194ca8 704e170 1a0079 13d21c17 993c39d b4f6764]-[938f35c 7694ed4 2d66fd8e 4288eb7 12e95827 1d4eb75 dd72691 efbf7d7 842f7ec]-[18433d64 2de04a3 3e162a33 b18e77e 154f8bc1 df835b8 aa8b90b 1196e445 1792de56]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("ScalarMult error, got %s, want %s", got, check)
    }
}

func Test_Point_Equal(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b PointJacobian

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    eq := a.Equal(&b)
    if eq != 1 {
        t.Errorf("Equal error, got %d", eq)
    }
}

func Test_Point_NotEqual(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b PointJacobian

    x1.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetUint32([9]uint32{0x11, 0x1, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF301, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z2.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    eq := a.Equal(&b)
    if eq == 1 {
        t.Errorf("NotEqual error, got %d", eq)
    }
}

func Test_Point_NewGenerator(t *testing.T) {
    var a Point

    a.NewGenerator()

    check := "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7-bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
    got := fmt.Sprintf("%x-%x", a.x.Bytes(), a.y.Bytes())

    if got != check {
        t.Errorf("NewGenerator error, got %s, want %s", got, check)
    }
}
