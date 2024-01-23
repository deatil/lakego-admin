package point

import (
    "strconv"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

type lookupTable struct {
    points [16]PointJacobian
}

func (v *lookupTable) Init(p *PointJacobian) {
    var p2 Point

    points := &v.points

    // We precompute 0,1,2,... times {x,y}.
    points[1].Set(&PointJacobian{
        x: p.x,
        y: p.y,
        z: field.Factor[1],
    })

    for i := 2; i < 8; i += 2 {
        points[i].Double(&points[i/2])
        points[i+1].AddMixed(&points[i], p2.FromJacobian(p))
    }
}

// index must be in [0, 15].
// Select sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (v *lookupTable) SelectInto(dest *PointJacobian, index uint32) {
    if index >= 16 {
        panic("cryptobin/sm2: out-of-bounds: " + strconv.Itoa(int(index)))
    }

    dest.Zero()

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        dest.Select(&v.points[i], mask)
    }
}

// point init tables
type pointTable struct {
    points [16]Point
}

// init
func (v *pointTable) Init(table []uint32) {
    var x, y [9]uint32

    points := &v.points

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        copy(x[:], table[0:])
        copy(y[:], table[9:])

        table = table[18:]

        points[i].x.SetUint32(x)
        points[i].y.SetUint32(y)
    }
}

// index must be in [0, 15].
// Select sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (v *pointTable) SelectInto(dest *Point, index uint32) {
    if index >= 16 {
        panic("cryptobin/sm2: out-of-bounds: " + strconv.Itoa(int(index)))
    }

    dest.Zero()

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        dest.Select(&v.points[i], mask)
    }
}

func pointSelectInto(table []uint32, dest *Point, index uint32) {
    var p pointTable
    p.Init(table)
    p.SelectInto(dest, index)
}
