package pkcs12

import (
    "testing"
    "encoding/asn1"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_hashByOID_fail(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    oidFail := asn1.ObjectIdentifier{1, 222, 643, 777, 12, 13, 5, 1}

    _, _, err := hashByOID(oidFail)
    if err == nil {
        t.Error("should throw panic")
    }

    check := "go-cryptobin/pkcs12: unsupported hash (OID: 1.222.643.777.12.13.5.1)"
    assertEqual(err.Error(), check, "Test_hashByOID_fail")
}

func Test_prfByOIDPBMAC1_fail(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    oidFail := asn1.ObjectIdentifier{1, 222, 643, 777, 12, 13, 5, 1}

    _, err := pbmac1PRFByOID(oidFail)
    if err == nil {
        t.Error("should throw panic")
    }

    check := "go-cryptobin/pkcs12: unsupported hash (OID: 1.222.643.777.12.13.5.1)"
    assertEqual(err.Error(), check, "Test_hashByOID_fail")
}

