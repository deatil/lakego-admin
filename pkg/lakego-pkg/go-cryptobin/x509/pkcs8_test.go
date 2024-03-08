package x509

import (
    "testing"
)

var Gost_PrikeyWithAttrs = `
-----BEGIN PRIVATE KEY-----
MIGiAgEAMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUDBwEBAgMEQIXnWrZ6
ajvbCU6x9jK49PgQqCP00T/lW3laXCXueMF8X4Q1y3N9zfOJT2s/IgyPJVrUhgtO
1Akp+Roh8bCPPlqgODA2BggqhQMCCQMIATEqBCi72ZvrBVW6mFL/bQeXeMTf8Jh8
p/diI7Cg8ig4mXg3tsIUf4vBi61b
-----END PRIVATE KEY-----
`

func Test_Check_Gost_PrikeyWithAttrs(t *testing.T) {
    pri := decodePEM(Gost_PrikeyWithAttrs)
    if len(pri) == 0 {
        t.Error("decodePEM prikey empty")
    }

    prikey, err := PasrsePKCS8Key(pri)
    if err != nil {
        t.Fatal(err)
    }

    attrs := prikey.GetAttributes()
    if len(attrs) == 0 {
        t.Error("attrs should not zero")
    }
}
