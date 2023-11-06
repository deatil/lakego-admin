package key

import (
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gost"
)

type namedCurveInfo struct {
    namedCurve *gost.Curve
    oid        asn1.ObjectIdentifier
}

var namedCurves = make([]namedCurveInfo, 0)

func AddNamedCurve(curve *gost.Curve, oid asn1.ObjectIdentifier)  {
    namedCurves = append(namedCurves, namedCurveInfo{
        namedCurve: curve,
        oid:        oid,
    })
}

func NamedCurveFromOid(oid asn1.ObjectIdentifier) *gost.Curve {
    for i := range namedCurves {
        cur := &namedCurves[i]
        if cur.oid.Equal(oid) {
            return cur.namedCurve
        }
    }

    return nil
}

func OidFromNamedCurve(curve *gost.Curve) (asn1.ObjectIdentifier, bool) {
    for i := range namedCurves {
        cur := &namedCurves[i]
        if cur.namedCurve.String() == curve.String() {
            return cur.oid, true
        }
    }

    return asn1.ObjectIdentifier{}, false
}
