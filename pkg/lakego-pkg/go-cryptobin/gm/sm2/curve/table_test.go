package curve

import (
    "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

func Test_lookupTable(t *testing.T) {
    var x, y, z field.Element
    var a, d PointJacobian
    var lt lookupTable

    x.SetUint32([9]uint32{0x11, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x12, 0x01})
    y.SetUint32([9]uint32{0x10, 0x0, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})
    z.SetUint32([9]uint32{0x10, 0x2, 0x1FFFF801, 0x3FFF, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x
    a.y = y
    a.z = z

    lt.Init(&a)
    lt.SelectInto(&d, 3)

    check := "[bddb8d5 4370701 30c25339 79624a5 1546a276 88db347 fcc2eb4 172f04cd d04016]-[2d79702 6882e59 3cc9b461 486e346 f81cdc5 18dd5e9 1fc4e6db 87b6db4 137ddbe7]-[8d157cc d85486c 918c140 2dd9af6 1dfac66 8a010e0 fb46b81 2357b9d a59b663]"
    got := fmt.Sprintf("%x-%x-%x", d.x.GetUint32(), d.y.GetUint32(), d.z.GetUint32())

    if got != check {
        t.Errorf("lookupTable error, got %s, want %s", got, check)
    }
}

func Test_pointSelectInto(t *testing.T) {
    var a Point

    pointSelectInto(precomputed[0:], &a, 3)

    check := "[1341b3b8 ee84e23 1edfa5b4 14e6030 19e87be9 92f533c 1665d96c 226653e a238d3e]-[f5c62c 95bb7a 1f0e5a41 28789c3 1f251d23 8726609 e918910 8096848 f63d028]"
    got := fmt.Sprintf("%x-%x", a.x.GetUint32(), a.y.GetUint32())

    if got != check {
        t.Errorf("pointSelectInto error, got %s, want %s", got, check)
    }
}
