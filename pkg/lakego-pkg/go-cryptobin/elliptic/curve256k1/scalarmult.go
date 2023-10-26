package curve256k1

import "sync"

func (p *PointJacobian) ScalarMult(q *PointJacobian, k []byte) *PointJacobian {
    s := normalizeScalar(k)

    var table lookupTable
    table.Init(q)

    var tmp PointJacobian
    var v, zero PointJacobian
    zero.Zero()
    v.Zero()

    // first byte
    b := s[0]
    table.SelectInto(&tmp, b>>4)
    v.Add(&v, &tmp)
    v.Double(&v)
    v.Double(&v)
    v.Double(&v)
    v.Double(&v)
    table.SelectInto(&tmp, b&0xf)
    v.Add(&v, &tmp)

    for i := 1; i < len(s); i++ {
        b := s[i]
        v.Double(&v)
        v.Double(&v)
        v.Double(&v)
        v.Double(&v)
        table.SelectInto(&tmp, b>>4)
        v.Add(&v, &tmp)

        v.Double(&v)
        v.Double(&v)
        v.Double(&v)
        v.Double(&v)
        table.SelectInto(&tmp, b&0xf)
        v.Add(&v, &tmp)
    }
    p.Set(&v)
    return p
}

var baseTable [64]lookupTable
var initOnce sync.Once

func initBaseTable() {
    initOnce.Do(func() {
        var gen Point
        var base PointJacobian
        base.FromAffine(gen.NewGenerator())
        for i := 0; i < 64; i++ {
            baseTable[i].Init(&base)
            base.Double(&base)
            base.Double(&base)
            base.Double(&base)
            base.Double(&base)
        }
    })
}

func (p *PointJacobian) ScalarBaseMult(k []byte) *PointJacobian {
    initBaseTable()

    s := normalizeScalar(k)

    var q PointJacobian
    q.FromAffine(new(Point).NewGenerator())

    var v PointJacobian
    v.Zero()
    for i, j := 0, len(baseTable)-1; i < len(s); i++ {
        b := s[i]

        // hi-nibble
        var tmp PointJacobian
        baseTable[j].SelectInto(&tmp, b>>4)
        v.Add(&v, &tmp)
        j--

        // low-nibble
        baseTable[j].SelectInto(&tmp, b&0xf)
        v.Add(&v, &tmp)
        j--
    }
    p.Set(&v)
    return p
}
