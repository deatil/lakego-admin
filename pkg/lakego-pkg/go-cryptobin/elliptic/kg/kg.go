package kg

import (
    "sync"
    "encoding/asn1"
)

var (
    OIDKG      = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1}
    OIDKG256r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 1}
    OIDKG384r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 2}
)

var once sync.Once

func KG256r1() *KGCurve {
    once.Do(initAll)
    return kg256r1
}

func KG384r1() *KGCurve {
    once.Do(initAll)
    return kg384r1
}
