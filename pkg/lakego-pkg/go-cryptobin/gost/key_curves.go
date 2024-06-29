package gost

import (
    "encoding/asn1"
)

type namedCurveInfo struct {
    namedCurve *Curve
    oid        asn1.ObjectIdentifier
}

var namedCurves = make([]namedCurveInfo, 0)

func AddNamedCurve(curve *Curve, oid asn1.ObjectIdentifier)  {
    namedCurves = append(namedCurves, namedCurveInfo{
        namedCurve: curve,
        oid:        oid,
    })
}

func NamedCurveFromOid(oid asn1.ObjectIdentifier) *Curve {
    for i := range namedCurves {
        cur := &namedCurves[i]
        if cur.oid.Equal(oid) {
            return cur.namedCurve
        }
    }

    return nil
}

func NamedCurveFromName(name string) *Curve {
    for i := range namedCurves {
        cur := &namedCurves[i]
        if cur.namedCurve.Name == name {
            return cur.namedCurve
        }
    }

    return nil
}

func OidFromNamedCurve(curve *Curve) (asn1.ObjectIdentifier, bool) {
    for i := range namedCurves {
        cur := &namedCurves[i]
        if cur.namedCurve.String() == curve.String() {
            return cur.oid, true
        }
    }

    return asn1.ObjectIdentifier{}, false
}
