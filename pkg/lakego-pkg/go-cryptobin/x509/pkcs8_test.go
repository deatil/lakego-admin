package x509

import (
    "bytes"
    "testing"
    "encoding/asn1"
    "crypto/x509/pkix"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
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

func Test_Update_Check(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := decodePEM(Gost_PrikeyWithAttrs)
    if len(pri) == 0 {
        t.Error("decodePEM prikey empty")
    }

    prikey, err := PasrsePKCS8Key(pri)
    if err != nil {
        t.Fatal(err)
    }

    newprikey, err := prikey.Marshal()
    assertNoError(err, "Test_Update_Check-Marshal")
    assertEqual(newprikey, pri, "Test_Update_Check-Marshal-Equal")

    var testOID = asn1.ObjectIdentifier{1, 3, 66, 77, 88, 99}
    var testEmptyOID = asn1.ObjectIdentifier{1, 3, 66, 77, 88, 99, 1010}
    var testBytes = []byte("test")
    var testPrivateKey = []byte("testPrivateKey")

    prikey.UpdateVersion(55)
    if prikey.Version != 55 {
        t.Error("UpdateVersion fail")
    }

    prikey.UpdateAlgo(pkix.AlgorithmIdentifier{
        Algorithm: testOID,
        Parameters: asn1.RawValue{
            FullBytes: testBytes,
        },
    })
    if !prikey.Algo.Algorithm.Equal(testOID) {
        t.Error("UpdateAlgo Algorithm fail")
    }
    if !bytes.Equal(prikey.Algo.Parameters.FullBytes, testBytes) {
        t.Error("UpdateAlgo Parameters fail")
    }

    prikey.UpdatePrivateKey(testPrivateKey)
    if !bytes.Equal(prikey.PrivateKey, testPrivateKey) {
        t.Error("UpdatePrivateKey fail")
    }

    var testAttr = asn1.RawValue{
        FullBytes: testBytes,
    }

    p8 := &pkcs8{}
    p8.AddAttribute(testAttr)
    assertEqual(p8.Attributes[0], testAttr, "Test_Update_Check-AddAttribute-Equal")

    // ==========

    var testBytesData = []byte("test33333333333")

    testBytes2, _ := asn1.Marshal(testBytes)
    testAttr2 := asn1.RawValue{
        FullBytes: testBytes2,
    }

    testBytes3, _ := asn1.Marshal(testBytesData)
    testAttr3 := asn1.RawValue{
        FullBytes: testBytes3,
    }

    p8 = &pkcs8{
        Attributes: make([]asn1.RawValue, 0),
    }
    err = p8.AddAttr(testOID, []asn1.RawValue{testAttr2})
    assertNoError(err, "Test_Update_Check-AddAttr")

    newAttr, _ := asn1.Marshal(pkcs8Attribute{
        Id: testOID,
        Values: []asn1.RawValue{testAttr2},
    })

    assertEqual(p8.Attributes[0].FullBytes, newAttr, "Test_Update_Check-AddAttr-Equal")

    attrss := p8.GetAttributes()
    assertEqual(len(attrss), 1, "Test_Update_Check-GetAttributes-Equal")

    assertEqual(p8.HasAttr(testOID), true, "Test_Update_Check-HasAttr-Equal")

    err = p8.UpdateAttr(testOID, []asn1.RawValue{testAttr3})
    assertNoError(err, "Test_Update_Check-UpdateAttr")

    attrss3 := p8.GetAttributes()
    assertEqual(len(attrss3), 1, "Test_Update_Check-UpdateAttr-GetAttributes-Equal")

    assertEqual(attrss3[0].Id, testOID, "Test_Update_Check-AddAttribute-testOID")
    assertEqual(attrss3[0].Values[0].FullBytes, testBytes3, "Test_Update_Check-AddAttribute-testOID")

    attrss6 := p8.GetAttribute(testOID)
    assertEqual(attrss6.Values[0].FullBytes, testBytes3, "Test_Update_Check-GetAttribute-testOID")

    attrssCount := p8.GetAttrCount(testOID)
    assertEqual(attrssCount, 1, "Test_Update_Check-GetAttrCount-Equal")

    attrssEmpty6 := p8.GetAttribute(testEmptyOID)
    assertEqual(len(attrssEmpty6.Values), 0, "Test_Update_Check-Empty-GetAttribute-Equal")

    p8.DeleteAttr(testOID)
    assertEqual(p8.HasAttr(testOID), false, "Test_Update_Check-DeleteAttr-Equal")

    attrss5 := p8.GetAttributes()
    assertEqual(len(attrss5), 0, "Test_Update_Check-DeleteAttr-GetAttributes-Equal")

    attrssCount2 := p8.GetAttrCount(testOID)
    assertEqual(attrssCount2, 0, "Test_Update_Check-DeleteAttr-GetAttrCount-Equal")
}
