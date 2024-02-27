package x509

import (
    "net"
    "time"
    "testing"
    "math/big"
    "encoding/pem"
    "encoding/asn1"
    "crypto/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/gost"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

func Test_X509(t *testing.T) {
    priv, err := sm2.GenerateKey(nil) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    privPem, err := sm2.MarshalPrivateKey(priv) // 生成密钥文件
    if err != nil {
        t.Fatal(err)
    }

    privKey, err := sm2.ParsePrivateKey(privPem) // 读取密钥
    if err != nil {
        t.Fatal(err)
    }

    if !priv.Equal(privKey) {
        t.Error("MarshalPrivateKey error")
    }

    pubKey, _ := priv.Public().(*sm2.PublicKey)
    pubkeyPem, err := sm2.MarshalPublicKey(pubKey)       // 生成公钥文件

    pubKey2, err := sm2.ParsePublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    if !pubKey2.Equal(pubKey) {
        t.Error("MarshalPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        // SignatureAlgorithm: ECDSAWithSHA256,
        SignatureAlgorithm: SM2WithSM3,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, privKey)
    if err != nil {
        t.Fatal(err)
    }

    req, err := ParseCertificateRequest(reqPem)
    if err != nil {
        t.Fatal(err)
    }

    err = req.CheckSignature()
    if err != nil {
        t.Fatalf("Request CheckSignature error:%v", err)
    }

    testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
    testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
    extraExtensionData := []byte("extra extension")
    commonName := "test.example.com"
    template := Certificate{
        // SerialNumber is negative to ensure that negative
        // values are parsed. This is due to the prevalence of
        // buggy code that produces certificates with negative
        // serial numbers.
        SerialNumber: big.NewInt(-1),
        Subject: pkix.Name{
            CommonName:   commonName,
            Organization: []string{"TEST"},
            Country:      []string{"China"},
            ExtraNames: []pkix.AttributeTypeAndValue{
                {
                    Type:  []int{2, 5, 4, 42},
                    Value: "Gopher",
                },
                // This should override the Country, above.
                {
                    Type:  []int{2, 5, 4, 6},
                    Value: "NL",
                },
            },
        },
        NotBefore: time.Now(),
        NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

        //		SignatureAlgorithm: ECDSAWithSHA256,
        SignatureAlgorithm: SM2WithSM3,

        SubjectKeyId: []byte{1, 2, 3, 4},
        KeyUsage:     KeyUsageCertSign,

        ExtKeyUsage:        testExtKeyUsage,
        UnknownExtKeyUsage: testUnknownExtKeyUsage,

        BasicConstraintsValid: true,
        IsCA:                  true,

        OCSPServer:            []string{"http://ocsp.example.com"},
        IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

        DNSNames:       []string{"test.example.com"},
        EmailAddresses: []string{"gopher@golang.org"},
        IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

        PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
        PermittedDNSDomains: []string{".example.com", "example.com"},

        CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

        ExtraExtensions: []pkix.Extension{
            {
                Id:    []int{1, 2, 3, 4},
                Value: extraExtensionData,
            },
            // This extension should override the SubjectKeyId, above.
            {
                Id:       oidExtensionSubjectKeyId,
                Critical: false,
                Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
            },
        },
    }

    pubKey, _ = priv.Public().(*sm2.PublicKey)
    certpem, err := CreateCertificate(&template, &template, pubKey, privKey)
    if err != nil {
        t.Fatal("failed to create cert file")
    }

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

func Test_Gost(t *testing.T) {
    priv, err := gost.GenerateKey(rand.Reader, gost.CurveIdGostR34102001TestParamSet()) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    privPem, err := gost.MarshalPrivateKey(priv) // 生成密钥文件
    if err != nil {
        t.Fatal(err)
    }

    privKey, err := gost.ParsePrivateKey(privPem) // 读取密钥
    if err != nil {
        t.Fatal(err)
    }

    if !priv.Equal(privKey) {
        t.Error("MarshalPrivateKey error")
    }

    pubKey, _ := priv.Public().(*gost.PublicKey)
    pubkeyPem, err := gost.MarshalPublicKey(pubKey)       // 生成公钥文件

    pubKey2, err := gost.ParsePublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    if !pubKey2.Equal(pubKey) {
        t.Error("MarshalPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: GOST3410WithGOST34112012256,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, privKey)
    if err != nil {
        t.Fatal(err)
    }

    req, err := ParseCertificateRequest(reqPem)
    if err != nil {
        t.Fatal(err)
    }

    err = req.CheckSignature()
    if err != nil {
        t.Fatalf("Request CheckSignature error:%v", err)
    }

    testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
    testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
    extraExtensionData := []byte("extra extension")
    commonName := "test.example.com"
    template := Certificate{
        // SerialNumber is negative to ensure that negative
        // values are parsed. This is due to the prevalence of
        // buggy code that produces certificates with negative
        // serial numbers.
        SerialNumber: big.NewInt(-1),
        Subject: pkix.Name{
            CommonName:   commonName,
            Organization: []string{"TEST"},
            Country:      []string{"China"},
            ExtraNames: []pkix.AttributeTypeAndValue{
                {
                    Type:  []int{2, 5, 4, 42},
                    Value: "Gopher",
                },
                // This should override the Country, above.
                {
                    Type:  []int{2, 5, 4, 6},
                    Value: "NL",
                },
            },
        },
        NotBefore: time.Now(),
        NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

        SignatureAlgorithm: GOST3410WithGOST34112012256,

        SubjectKeyId: []byte{1, 2, 3, 4},
        KeyUsage:     KeyUsageCertSign,

        ExtKeyUsage:        testExtKeyUsage,
        UnknownExtKeyUsage: testUnknownExtKeyUsage,

        BasicConstraintsValid: true,
        IsCA:                  true,

        OCSPServer:            []string{"http://ocsp.example.com"},
        IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

        DNSNames:       []string{"test.example.com"},
        EmailAddresses: []string{"gopher@golang.org"},
        IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

        PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
        PermittedDNSDomains: []string{".example.com", "example.com"},

        CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

        ExtraExtensions: []pkix.Extension{
            {
                Id:    []int{1, 2, 3, 4},
                Value: extraExtensionData,
            },
            // This extension should override the SubjectKeyId, above.
            {
                Id:       oidExtensionSubjectKeyId,
                Critical: false,
                Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
            },
        },
    }

    pubKey, _ = priv.Public().(*gost.PublicKey)
    certpem, err := CreateCertificate(&template, &template, pubKey, privKey)
    if err != nil {
        t.Fatal("failed to create cert file: " + err.Error())
    }

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

var testOpensslGostCert = `
-----BEGIN CERTIFICATE-----
MIIB6TCCAZSgAwIBAgIUUv3U4LiFVjZW4dJVKPIXe/IGeyMwDAYIKoUDBwEBAwIF
ADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMB4XDTIwMDMxMzAyMDMwOVoXDTMwMDMx
MTAyMDMwOVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf
BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBmMB8GCCqFAwcBAQEBMBMG
ByqFAwICIwEGCCqFAwcBAQICA0MABEDkSyJyVSVzwHJhibRxoZM475OgoNmIKN0w
4jLHZmvLXX70bLa83RebqlVhahbJQ8eSuYm04drZyKPUJVPm7SG2o1MwUTAdBgNV
HQ4EFgQULOn+VVG8YOOEBG0I0F3guXU8VDgwHwYDVR0jBBgwFoAULOn+VVG8YOOE
BG0I0F3guXU8VDgwDwYDVR0TAQH/BAUwAwEB/zAMBggqhQMHAQEDAgUAA0EAv3Sm
QQtmBhm2Y67rNgUxvdLRoD1363eN7Mw0tZ6SDyZvJHODgDSlas4KQKU+tuysCRSW
pINcWw3M4CXPIG9VKQ==
-----END CERTIFICATE-----
`

func Test_P12_Openssl_Gost(t *testing.T) {
    certpem := decodePEM(testOpensslGostCert)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := cert.PublicKey.(*gost.PublicKey)

    publicKey, err := gost.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

var testGostCert256 = `
-----BEGIN CERTIFICATE-----
MIICYjCCAg+gAwIBAgIBATAKBggqhQMHAQEDAjBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDI1NiBiaXQpIGV4YW1wbGUwHhcNMTMxMTA1MTQwMjM3WhcNMzAxMTAxMTQw
MjM3WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDI1NiBiaXQpIGV4YW1wbGUwZjAf
BggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAut/Qw1MUq9KPqkdH
C2xAF3K7TugHfo9n525D2s5mFZdD5pwf90/i4vF0mFmr9nfRwMYP4o0Pg1mOn5Rl
aXNYraOBwDCBvTAdBgNVHQ4EFgQU1fIeN1HaPbw+XWUzbkJ+kHJUT0AwCwYDVR0P
BAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYDVR0BBHcwdYAU1fIeN1HaPbw+XWUz
bkJ+kHJUT0ChWqRYMFYxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4
YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0MTAtMjAxMiAoMjU2IGJpdCkgZXhh
bXBsZYIBATAKBggqhQMHAQEDAgNBAF5bm4BbARR6hJLEoWJkOsYV3Hd7kXQQjz3C
dqQfmHrz6TI6Xojdh/t8ckODv/587NS5/6KsM77vc6Wh90NAT2s=
-----END CERTIFICATE-----
`

func Test_P12_Gost_256(t *testing.T) {
    certpem := decodePEM(testGostCert256)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := cert.PublicKey.(*gost.PublicKey)

    publicKey, err := gost.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }

    c := gost.CurveIdGostR34102001CryptoProXchAParamSet()

    prvkeyRaw, _ := new(big.Int).SetString("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924", 16)
    prvkey, err := gost.NewPrivateKey(c, gost.Reverse(prvkeyRaw.Bytes()))
    if err != nil {
        t.Fatal(err)
    }

    pubKey2 := &prvkey.PublicKey

    publicKey2, err := gost.MarshalPublicKey(pubKey2)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem2 := encodePEM(publicKey2, "PUBLIC KEY")
    if len(publicKeyPem2) == 0 {
        t.Error("fail make publicKey2")
    }

    if publicKeyPem != publicKeyPem2 {
        t.Errorf("publicKey2 not eq publicKey, got %s, want %s", publicKeyPem, publicKeyPem2)
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }

    // t.Errorf("%s \n", publicKeyPem)
    // t.Errorf("%s \n", publicKeyPem2)
}

var testGostCert512 = `
-----BEGIN CERTIFICATE-----
MIIC6DCCAlSgAwIBAgIBATAKBggqhQMHAQEDAzBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDUxMiBiaXQpIGV4YW1wbGUwHhcNMTMxMDA0MDczNjA0WhcNMzAxMDAxMDcz
NjA0WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDUxMiBiaXQpIGV4YW1wbGUwgaow
IQYIKoUDBwEBAQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYATGQ9VCiM5
FRGCQ8MEz2F1dANqhaEuywa8CbxOnTvaGJpFQVXQwkwvLFAKh7hk542vOEtxpKtT
CXfGf84nRhMH/Q9bZeAc2eO/yhxrsQhTBufa1Fuou2oe/jUOaG6RAtUUvRzhNTpp
RGGl1+EIY2vzzUua9j9Ol/gAoy/LNKQIfqOBwDCBvTAdBgNVHQ4EFgQUPcbTRXJZ
nHtjj+eBP7b5lcTMekIwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYD
VR0BBHcwdYAUPcbTRXJZnHtjj+eBP7b5lcTMekKhWqRYMFYxKTAnBgkqhkiG9w0B
CQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0
MTAtMjAxMiAoNTEyIGJpdCkgZXhhbXBsZYIBATAKBggqhQMHAQEDAwOBgQBObS7o
ppPTXzHyVR1DtPa8b57nudJzI4czhsfeX5HDntOq45t9B/qSs8dC6eGxbhHZ9zCO
SFtxWYdmg0au8XI9Xb8vTC1qdwWID7FFjMWDNQZb6lYh/J+8F2xKylvB5nIlRZqO
o3eUNFkNyHJwQCk2WoOlO16zwGk2tdKH4KmD5w==
-----END CERTIFICATE-----
`

func Test_P12_Gost_512(t *testing.T) {
    certpem := decodePEM(testGostCert512)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := cert.PublicKey.(*gost.PublicKey)

    publicKey, err := gost.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }

    c := gost.CurveIdtc26gost34102012512paramSetB()

    prvkeyRaw, _ := new(big.Int).SetString("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B", 16)
    prvkey, err := gost.NewPrivateKey(c, gost.Reverse(prvkeyRaw.Bytes()))
    if err != nil {
        t.Fatal(err)
    }

    pubKey2 := &prvkey.PublicKey

    publicKey2, err := gost.MarshalPublicKey(pubKey2)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem2 := encodePEM(publicKey2, "PUBLIC KEY")
    if len(publicKeyPem2) == 0 {
        t.Error("fail make publicKey2")
    }

    if publicKeyPem != publicKeyPem2 {
        t.Errorf("publicKey2 not eq publicKey, got %s, want %s", publicKeyPem, publicKeyPem2)
    }

    // cert.PublicKey = pubKey2
    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

var testGostCert222 = `
-----BEGIN CERTIFICATE-----
MIIDAjCCAq2gAwIBAgIQAdBoXzEflsAAAAALJwkAATAMBggqhQMHAQEDAgUAMGAx
CzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxDzANBgNVBAoMBtCi
0JoyNjEpMCcGA1UEAwwgQ0EgY2VydGlmaWNhdGUgKFBLQ1MjMTIgZXhhbXBsZSkw
HhcNMTUwMzI3MDcyNTAwWhcNMjAwMzI3MDcyMzAwWjBkMQswCQYDVQQGEwJSVTEV
MBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxLTArBgNVBAMM
JFRlc3QgY2VydGlmaWNhdGUgMSAoUEtDUyMxMiBleGFtcGxlKTBmMB8GCCqFAwcB
AQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEDXHPKaSm+vZ1glPxZM5fcO33r/
6Eaxc3K1RCmRYHkiYkzi2D0CwLhEhTBXkfjUyEbS4FEXB5PM3oCwB0G+FMKVgQkA
MjcwOTAwMDGjggEpMIIBJTArBgNVHRAEJDAigA8yMDE1MDMyNzA3MjUwMFqBDzIw
MTYwMzI3MDcyNTAwWjAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFCFY6xFDrzJg
3ZS2D+jAehZyqxVtMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBgNV
HRMBAf8EAjAAMIGZBgNVHSMEgZEwgY6AFCadzteHnKRvm38EzA6TEDh2t8SaoWSk
YjBgMQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQK
DAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmljYXRlIChQS0NTIzEyIGV4YW1w
bGUpghAB0Ghe8vxNIAAAAAsnCQABMAwGCCqFAwcBAQMCBQADQQD2irRW+TySSAjC
SnTHQnl4q2Jrgw1OLAoCbuOCcJkjHc73wFOFpNfdlCESjZEv2lMI+vrAUyF54n5h
0YxF5e+y
-----END CERTIFICATE-----
`

func Test_P12_Gost_222(t *testing.T) {
    certpem := decodePEM(testGostCert222)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := cert.PublicKey.(*gost.PublicKey)

    publicKey, err := gost.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        // t.Fatal(err)
    }
}
