package edwards448

import (
    "sync"
    "crypto/subtle"
)

type lookupTable struct {
    points [8]Point
}

var initBasepointOnce sync.Once
var varBasepointTable [56]lookupTable

// basepointTable is a set of 32 affineLookupTables, where table i is generated
// from 256i * basepoint. It is precomputed the first time it's used.
func basepointTable() *[56]lookupTable {
    initBasepointOnce.Do(func() {
        p := NewGeneratorPoint()
        for i := 0; i < 56; i++ {
            varBasepointTable[i].Init(p)
            for j := 0; j < 8; j++ {
                p.Add(p, p)
            }
        }
    })
    return &varBasepointTable
}

var initBasepointNAFOnce sync.Once
var varBasepointNAFTable nafLookupTable8

func basepointNAFTable() *nafLookupTable8 {
    initBasepointNAFOnce.Do(func() {
        varBasepointNAFTable.Init(NewGeneratorPoint())
    })
    return &varBasepointNAFTable
}

func (v *lookupTable) Init(p *Point) {
    // Goal: v.points[i] = (i+1)*Q, i.e., Q, 2Q, ..., 8Q
    // This allows lookup of -8Q, ..., -Q, 0, Q, ..., 8Q
    points := &v.points
    points[0].Set(p)
    for i := 1; i < 8; i++ {
        var v Point
        points[i].Set(v.Add(&points[i-1], p))
    }
}

// Set dest to x*Q, where -8 <= x <= 8, in constant time.
func (v *lookupTable) SelectInto(dest *Point, x int8) {
    // Compute xabs = |x|
    xmask := x >> 7
    xabs := uint8((x + xmask) ^ xmask)

    dest.Zero()
    for i := 1; i <= 8; i++ {
        // Set dest = i*Q if |x| = i
        cond := subtle.ConstantTimeByteEq(xabs, uint8(i))
        dest.Select(&v.points[i-1], dest, cond)
    }
    // Now dest = |x|*Q, conditionally negate to get x*Q
    dest.CondNeg(int(xmask & 1))
}

type nafLookupTable5 struct {
    points [8]Point
}

// Builds a lookup table at runtime. Fast.
func (v *nafLookupTable5) Init(q *Point) {
    // Goal: v.points[i] = (2*i+1)*Q, i.e., Q, 3Q, 5Q, ..., 15Q
    // This allows lookup of -15Q, ..., -3Q, -Q, 0, Q, 3Q, ..., 15Q

    v.points[0].Set(q)
    var q2 Point
    q2.Add(q, q)
    for i := 1; i < 8; i++ {
        v.points[i].Add(&v.points[i-1], &q2)
    }
}

// Given odd x with 0 < x < 2^4, return x*Q (in variable time).
func (v *nafLookupTable5) SelectInto(dest *Point, x int8) {
    *dest = v.points[x/2]
}

type nafLookupTable8 struct {
    points [64]Point
}

// Builds a lookup table at runtime. Fast.
func (v *nafLookupTable8) Init(q *Point) {
    // Goal: v.points[i] = (2*i+1)*Q, i.e., Q, 3Q, 5Q, ..., 63Q
    // This allows lookup of -63Q, ..., -3Q, -Q, 0, Q, 3Q, ..., 63Q

    v.points[0].Set(q)
    var q2 Point
    q2.Add(q, q)
    for i := 1; i < 64; i++ {
        v.points[i].Add(&v.points[i-1], &q2)
    }
}

// Given odd x with 0 < x < 2^7, return x*Q (in variable time).
func (v *nafLookupTable8) SelectInto(dest *Point, x int8) {
    *dest = v.points[x/2]
}
