package ber

import (
    "testing"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/tool/bmp_string"
    cryptobin_asn1 "github.com/deatil/go-cryptobin/ber/asn1"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var sm2Pkcs12 = "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w0BBwGggCSABIHNMIHKMIHHBgsqhkiG" +
"9w0BDAoBAqB2MHQwKAYKKoZIhvcNAQwBAzAaBBRBCcN+h46YwoEjCwYsx5R2Ggq3HgICBAAESFoOSL36" +
"Ku1nQYesdqh09xuQFCbr5Ozm5+aF91Bbs0tdRheyKY8JvC4VCzX2AsCrevOFb3io6teNdkcmFOeDOhSE" +
"VYuzJIHZZTFAMBkGCSqGSIb3DQEJFDEMHgoAQQAgAEsAZQB5MCMGCSqGSIb3DQEJFTEWBBSlqw4sTrXP" +
"Y1Io0OetvRz8sQyBQgAAAAAAADCABgkqhkiG9w0BBwaggDCAAgEAMIAGCSqGSIb3DQEHATAoBgoqhkiG" +
"9w0BDAEGMBoEFJb7ThL0KhfqB5ov1gQFeYRZWmZ/AgIEAKCABIICwBv1XgH3DfbaauQS27Gb036glq1K" +
"n/seDdCLdUROkxMa1HzXiyeDGB48ekgHYSLqzCNdnry2NZvMWoVPTaYvgF04DhZxPTcSYxWOPQL2+LX0" +
"GwEdjidQvGF1jze+R4uUxyXg9HXmxJ7jtl5djgHsPVeKIaQXSHQCcM1gYwsGDkV14zhrUfDiCw7LxMMg" +
"9To+x3g0Tx/ZcuCF5gmj8jgzsM7AqlPp/+UrVri/LB+mDE/IhRWL3Bkp+wBrTrIoQFLGQVQS3McWX+tx" +
"C4OXtLzTjoTu5VosvXDDxDhsrSfZNNztZTw6z2l48IY5O7vMUsFkW7eCkiLuek5ck1uhv50lqNvEEbsk" +
"uMj7j3fyZnBZAj0ieODo3Uu6fdKpTy0ysmKcPDMMES/5ASjDz3Zk/56vLr09s7uTTH4+xOZViP/T5y28" +
"40qrcefN2fmtOtyuUGO71ul+/LpXKch4atDR9jSv5ovyXhKKxfCOfHW2oV43aJwA66+uElR+ZsjwyLmA" +
"p0f12HdxeKJIWX4yDQiAJ9n/F3W3nBMpmZBNwEVdUE6+OoZUU93dD6BExMC27DuiaH622Mi2ydfkW+l2" +
"frehlTl0CmontrmpkJ30u/U25x6fI8wB0aXVd3IzWPYe0yMdnPZlOLajjer2DU6T4KD6spR3Cp0Vg1GW" +
"XTTj3gROAw9tKbJCWKLCkadhzHSnJ1Y9edjcwmIOWBZtM94julcKeviMW0DSwHojJy4bD2DO7fQv+JPg" +
"uG6Xlm5zajxOsnuUy0AzqRywTKplCQwa/U9i65FNBhsRSNE2Cmx8EXuWMxigQO3gyyQsUMrIpoUSzzQL" +
"vcIE5UCMvP69G5r5C9TSvQ2pKeAvkUIckMZkaA/lMqKkM55dOeFa60AX/Qj2WO0Yu6y18eaMSXnvwMWv" +
"B2UywrHDBB4iEu2+kNke7EUSzQbItlBZzJgAAAAAAAAAAAAAAAAAAAAAAAAwPTAhMAkGBSsOAwIaBQAE" +
"FJbJE8lKP08n4Y6jWYZcGrL6sy2gBBSkmhIJK3GKeGqMUxotT1on92p3FgICBAAAAA=="

func Test_SM2Pkcs12(t *testing.T) {
    ber, err := base64.StdEncoding.DecodeString(sm2Pkcs12)
    if err != nil {
        t.Errorf("err: %v", err)
    }

    pfx := new(PfxPdu)
    if _, err = cryptobin_asn1.Unmarshal(ber, pfx); err != nil {
        t.Errorf("Unmarshal err: %v", err)
    }

    if pfx.Version != 3 {
        t.Errorf("Version err: %d", pfx.Version)
    }

    if _, err = cryptobin_asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
        t.Errorf("Unmarshal2 err: %v", err)
    }

    data := pfx.AuthSafe.Content.Bytes

    var authenticatedSafes = make([]cryptobin_asn1.RawValue, 0)

    for {
        var authenticatedSafe cryptobin_asn1.RawValue
        data, err = cryptobin_asn1.Unmarshal(data, &authenticatedSafe)
        if err != nil {
            t.Errorf("Unmarshal octet err: %v", err)
        }

        authenticatedSafes = append(authenticatedSafes, authenticatedSafe)

        if len(data) == 0 {
            break
        }
    }

    password := "12345678"
    newPassword, err := bmp_string.BmpStringZeroTerminated(password)
    if err != nil {
        t.Errorf("password err: %v", err)
    }

    checkData := make([]byte, 0)
    for _, as := range authenticatedSafes {
        checkData = append(checkData, as.Bytes...)
    }

    err = pfx.MacData.Verify(checkData, newPassword)
    if err != nil {
        t.Errorf("password is error")
    }

    var ass []ContentInfo
    _, err = cryptobin_asn1.Unmarshal(checkData, &ass)
    if err != nil {
        t.Errorf("Unmarshal octet err: %v", err)
    }
}

func Test_SM2Pkcs12_Decode(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ber, err := base64.StdEncoding.DecodeString(sm2Pkcs12)
    if err != nil {
        t.Errorf("err: %v", err)
    }

    password := "12345678"

    privateKey, cert, err := Decode(ber, password)
    if err != nil {
        t.Errorf("SM2Pkcs12_Decode err: %v", err)
    }

    assertNotEmpty(privateKey, "SM2Pkcs12_Decode")
    assertNotEmpty(cert, "SM2Pkcs12_Decode")
}

func Test_P12_SM2Pkcs12_Decode(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotBool := cryptobin_test.AssertNotBoolT(t)

    ber, err := base64.StdEncoding.DecodeString(sm2Pkcs12)
    if err != nil {
        t.Errorf("err: %v", err)
    }

    password := "12345678"

    p12, err := LoadFromBytes(ber, password)
    if err != nil {
        t.Errorf("P12_SM2Pkcs12_Decode err: %v", err)
    }

    privateKey, _, _ := p12.GetPrivateKey()
    cert, _, _ := p12.GetCert()

    assertNotEmpty(privateKey, "P12_SM2Pkcs12_Decode")
    assertNotEmpty(cert, "P12_SM2Pkcs12_Decode")

    assertBool(p12.HasPrivateKey(), "P12_SM2Pkcs12_Decode-HasPrivateKey")
    assertBool(p12.HasCert(), "P12_SM2Pkcs12_Decode-HasCert")

    assertNotBool(p12.HasCaCert(), "P12_SM2Pkcs12_Decode-HasCaCert")
    assertNotBool(p12.HasTrustStore(), "P12_SM2Pkcs12_Decode-HasTrustStore")
    assertNotBool(p12.HasSecretKey(), "P12_SM2Pkcs12_Decode-HasSecretKey")

}
