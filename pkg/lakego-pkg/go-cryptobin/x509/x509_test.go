package x509

import (
    "net"
    "time"
    "testing"
    "math/big"
    "encoding/pem"
    "encoding/asn1"
    "encoding/base64"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
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

func Test_RSA(t *testing.T) {
    priv, err := rsa.GenerateKey(rand.Reader, 1024) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := priv.Public().(*rsa.PublicKey)
    pubkeyPem, err := x509.MarshalPKIXPublicKey(pubKey) // 生成公钥文件

    pubKey2, err := x509.ParsePKIXPublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    pubKey22, _ := pubKey2.(*rsa.PublicKey)

    if !pubKey22.Equal(pubKey) {
        t.Error("MarshalPKIXPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: SHA256WithRSA,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, priv)
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
        SignatureAlgorithm: SHA256WithRSA,

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

    pubKey, _ = priv.Public().(*rsa.PublicKey)
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
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

func Test_SM3WithRSA(t *testing.T) {
    priv, err := rsa.GenerateKey(rand.Reader, 1024) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := priv.Public().(*rsa.PublicKey)
    pubkeyPem, err := x509.MarshalPKIXPublicKey(pubKey) // 生成公钥文件

    pubKey2, err := x509.ParsePKIXPublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    pubKey22, _ := pubKey2.(*rsa.PublicKey)

    if !pubKey22.Equal(pubKey) {
        t.Error("MarshalPKIXPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: SM3WithRSA,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, priv)
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

        SignatureAlgorithm: SM3WithRSA,

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

    pubKey, _ = priv.Public().(*rsa.PublicKey)
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
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

func Test_DSA(t *testing.T) {
    priv := &dsa.PrivateKey{}
    dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160)
    dsa.GenerateKey(priv, rand.Reader)

    pubKey := &priv.PublicKey

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: DSAWithSHA1,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, priv)
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

        SignatureAlgorithm: DSAWithSHA1,

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

    pubKey = &priv.PublicKey
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
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

func Test_ECDSA(t *testing.T) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := priv.Public().(*ecdsa.PublicKey)
    pubkeyPem, err := x509.MarshalPKIXPublicKey(pubKey) // 生成公钥文件

    pubKey2, err := x509.ParsePKIXPublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    pubKey22, _ := pubKey2.(*ecdsa.PublicKey)

    if !pubKey22.Equal(pubKey) {
        t.Error("MarshalPKIXPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: ECDSAWithSHA256,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, priv)
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

        SignatureAlgorithm: ECDSAWithSHA256,

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

    pubKey, _ = priv.Public().(*ecdsa.PublicKey)
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
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

func Test_Ed25519(t *testing.T) {
    pubKey, priv, err := ed25519.GenerateKey(rand.Reader) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    pubkeyPem, err := x509.MarshalPKIXPublicKey(pubKey) // 生成公钥文件

    pubKey2, err := x509.ParsePKIXPublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    pubKey22, _ := pubKey2.(ed25519.PublicKey)

    if !pubKey22.Equal(pubKey) {
        t.Error("MarshalPKIXPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        SignatureAlgorithm: PureEd25519,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, priv)
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

        SignatureAlgorithm: PureEd25519,

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

    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
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

func Test_SM2(t *testing.T) {
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
        NotAfter:  time.Date(2023, time.October, 10, 12, 1, 1, 1, time.UTC),

        // SignatureAlgorithm: ECDSAWithSHA256,
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
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
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
    certpem, err := CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
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

var testSM2RootCaCert = `
-----BEGIN CERTIFICATE-----
MIIB4DCCAYagAwIBAgIBADAKBggqgRzPVQGDdTBGMQswCQYDVQQGEwJBQTELMAkG
A1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEQMA4GA1UEAwwHcm9v
dCBjYTAgFw0yMzAyMjIwMjMwMTNaGA8yMTIzMDEyOTAyMzAxM1owRjELMAkGA1UE
BhMCQUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQxEDAO
BgNVBAMMB3Jvb3QgY2EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASN55Ju2pvU
Bi8UrWHc4ZaKnsqiFPWfcM/6H2Gu/VQ7I1oVnyPktvlTrtwhSy6K43JoCnjVPHrq
jOXxnkOtGVDVo2MwYTAdBgNVHQ4EFgQUxu7mMmVaB3vq7JRi8UEFHcxVFY4wHwYD
VR0jBBgwFoAUxu7mMmVaB3vq7JRi8UEFHcxVFY4wDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIhAIz7tgrp7LmOQEJGPAU3
8m9PNzMOTqGWZqux8CxIuEGjAiB4cFVYQ4sTCYb/4fNayKYO1FH+Q2Cc7xGq7WPd
knwWpw==
-----END CERTIFICATE-----
`
var testSM2SubCaCert = `
-----BEGIN CERTIFICATE-----
MIIB4zCCAYigAwIBAgIBATAKBggqgRzPVQGDdTBGMQswCQYDVQQGEwJBQTELMAkG
A1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEQMA4GA1UEAwwHcm9v
dCBjYTAgFw0yMzAyMjIwMjMwMTNaGA8yMTIzMDEyOTAyMzAxM1owRTELMAkGA1UE
BhMCQUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQxDzAN
BgNVBAMMBnN1YiBjYTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABH0feWwae0S0
w4QQA5cBGYwaQPaxZFcLzIqph+I6BQQCGXaIAabqpO0zjAyf1twYmoM3ZRLJgbZz
HE/2rRMPBiajZjBkMB0GA1UdDgQWBBSsYesigGJZCD6WyNF/znRcAq88mTAfBgNV
HSMEGDAWgBTG7uYyZVoHe+rslGLxQQUdzFUVjjASBgNVHRMBAf8ECDAGAQH/AgEA
MA4GA1UdDwEB/wQEAwIBhjAKBggqgRzPVQGDdQNJADBGAiEApoHDue1bzGukE97O
BqQbboU1d3jqNg4gAgpMe5fFIosCIQDwndSp7Tc3DZ0QCifXKNqgykjepsWTPZ3R
NrMzM0rflg==
-----END CERTIFICATE-----
`

func Test_P12_SM2(t *testing.T) {
    certpem := decodePEM(testSM2RootCaCert)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, ok := cert.PublicKey.(*sm2.PublicKey)
    if !ok {
        t.Fatal("PublicKey is not sm2 PublicKey")
    }

    publicKey, err := sm2.MarshalPublicKey(pubKey)
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

    // ==========

    subCertpem := decodePEM(testSM2SubCaCert)

    subCert, err := ParseCertificate(subCertpem)
    if err != nil {
        t.Fatal(err)
    }

    // use root ca PublicKey to Check Signature
    subCert.PublicKey = pubKey
    err = subCert.CheckSignature(subCert.SignatureAlgorithm, subCert.RawTBSCertificate, subCert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

var testWeappRSACert = `
-----BEGIN CERTIFICATE-----
MIID0jCCArqgAwIBAgIUeE+Yy7vM/o+eHHsfM+1bGJJEZTQwDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCQ04xEzARBgNVBAoTClRlbnBheS5jb20xHTAbBgNVBAsT
FFRlbnBheS5jb20gQ0EgQ2VudGVyMRswGQYDVQQDExJUZW5wYXkuY29tIFJvb3Qg
Q0EwHhcNMjIwOTA1MDgzOTIyWhcNMjcwOTA0MDgzOTIyWjBkMRswGQYDVQQDDBJ3
eGQ5MzBlYTVkNWEyNThmNGYxFTATBgNVBAoMDFRlbmNlbnQgSW5jLjEOMAwGA1UE
CwwFV3hnTXAxCzAJBgNVBAYMAkNOMREwDwYDVQQHDAhTaGVuWmhlbjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5D9qlkCmk1kr3FpF0e9pc3kGsvz5RA
0/YRny9xPKIyV2UVMDZvRQ+mDHsiQQFE6etg457KFYSxTDKtItbdl6hJQVGeAvg0
mqPYE9SkHRGTfL/AnXRbKBG2GC2OcaPSAprsLOersjay2me+9pF8VHybV8aox78A
NsU75G/OO3V1iEE0s5Pmglqk8DEiw9gB/dGJzsNfXwzvyJyiUP9ZujYexyjsS+/Z
GdSOUkqL/th+16yHj8alcdyga6YGfWEDyWkt/i/B28cwx4nzwk8xgrurifPaLuMk
0+9wJQLCfAn/f7zyHrC8PcD1XvvRt9VBNMBASXs3710ODyyVf2lkMgkCAwEAAaOB
gTB/MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMGUGA1UdHwReMFwwWqBYoFaGVGh0
dHA6Ly9ldmNhLml0cnVzLmNvbS5jbi9wdWJsaWMvaXRydXNjcmw/Q0E9MUJENDIy
MEU1MERCQzA0QjA2QUQzOTc1NDk4NDZDMDFDM0U4RUJEMjANBgkqhkiG9w0BAQsF
AAOCAQEAL2MK9tYu+ljLVBlSbfEeaKyF07TN+G31Ya5NBzeS1ZCx4joUEIyACWmG
fUkKNKiKV+EMzxeEhKRso1Qif3E7Ipl+PQBoQw6OSR/jFHciYurnGR9CLkL03Zo1
qw1Xetv9OipsvlpA0SOWc207e/XpGdm8C7FMXM6bzvVp8I/STTjC1vqjIZu9WavI
RgGM4jyAPz2XogUq0BNijef8BXbbav9fAsXjHSwn5BQv4iLms3fiLm/eoyQ6dZ2R
oTudrlcyr1bG4vwETLmHF+3yfVp9dpvJ+lyfiviwDwyfa8t2WlJm27DuF4vWoxir
mjgj9tDutIFqxLIovLyg3uiAYtSQ/Q==
-----END CERTIFICATE-----
`

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
func Test_P12_RSA_Weapp(t *testing.T) {
    certpem := decodePEM(testWeappRSACert)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
    if !ok {
        t.Fatal("PublicKey is not rsa PublicKey")
    }

    publicKey, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }
}

var testWeappSM2Cert = `
-----BEGIN CERTIFICATE-----
MIICpTCCAkygAwIBAgIUaB2+dl2EhYIJt1KU3zYVk2Xb7+4wCgYIKoEcz1UBg3Uw
gaUxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ0RvbmcxETAPBgNVBAcMCFNo
ZW5aaGVuMRUwEwYDVQQKDAxUZW5jZW50IEluYy4xFjAUBgNVBAsMDVd4RGV2UGxh
dGZvcm0xFjAUBgNVBAMMDVd4RGV2UGxhdGZvcm0xKDAmBgkqhkiG9w0BCQEWGVd4
RGV2UGxhdGZvcm1AdGVuY2VudC5jb20wIhgPMjAyMjA5MDUxMjI0NTFaGA8yMDMy
MDkwMjEyMjQ1MVowgZgxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ0Rvbmcx
ETAPBgNVBAcMCFNoZW5aaGVuMRUwEwYDVQQKDAxUZW5jZW50IEluYy4xDjAMBgNV
BAsMBVd4Z01wMRswGQYDVQQDDBJ3eDkzYTRjMDQ2MWJhNTg5YjQxHjAcBgkqhkiG
9w0BCQEWD3dlaXhpbm1wQHFxLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BCqW4Oxv3dEXgjs2mZNzt0lZIhaERohbJFxM3Nv4GKx70EDHIOYpo2ue9HEO8u28
dXszQOG4xxDxbW4Y/If0SoqjYTBfMB8GA1UdIwQYMBaAFOZbGwNxANNz09qKnp4u
iCDA9EJXMB0GA1UdDgQWBBThaf6MTqwNkDXulajs6lTR5Dkc2zAMBgNVHRMBAf8E
AjAAMA8GA1UdDwEB/wQFAwMHwAAwCgYIKoEcz1UBg3UDRwAwRAIgOp0c64QSLUHx
vbiPw/27dIcItvsN2F6m7VN41xebJx0CIHL0bp5okshjBF38XM07m4nWw55zAmmF
EJc5Zq55kLC8
-----END CERTIFICATE-----
`

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
func Test_P12_SM2_Weapp(t *testing.T) {
    certpem := decodePEM(testWeappSM2Cert)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, ok := cert.PublicKey.(*sm2.PublicKey)
    if !ok {
        t.Fatal("PublicKey is not sm2 PublicKey")
    }

    publicKey, err := sm2.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }
}

var certBytes = "MIIE0jCCA7qgAwIBAgIQWcvS+TTB3GwCAAAAAGEAWzANBgkqhkiG9w0BAQsFADBCMQswCQYD" +
    "VQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMg" +
    "Q0EgMU8xMB4XDTIwMDQwMTEyNTg1NloXDTIwMDYyNDEyNTg1NlowaTELMAkGA1UEBhMCVVMx" +
    "EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoT" +
    "Ckdvb2dsZSBMTEMxGDAWBgNVBAMTD21haWwuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG" +
    "SM49AwEHA0IABO+dYiPnkFl+cZVf6mrWeNp0RhQcJSBGH+sEJxjvc+cYlW3QJCnm57qlpFdd" +
    "pz3MPyVejvXQdM6iI1mEWP4C2OujggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww" +
    "CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUI6pZhnQ/lQgmPDwSKR2A54G7" +
    "AS4wHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBWMCcG" +
    "CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYBBQUHMAKGH2h0" +
    "dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwLAYDVR0RBCUwI4IPbWFpbC5nb29nbGUu" +
    "Y29tghBpbmJveC5nb29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisGAQQB1nkC" +
    "BQMwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5wa2kuZ29vZy9HVFMxTzEuY3JsMIIB" +
    "AwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAsh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+L" +
    "kF4AAAFxNgmxKgAABAMARzBFAiEA12/OHdTGXQ3qHHC3NvYCyB8aEz/+ZFOLCAI7lhqj28sC" +
    "IG2/7Yz2zK6S6ai+dH7cTMZmoFGo39gtaTqtZAqEQX7nAHUAXqdz+d9WwOe1Nkh90EngMnqR" +
    "mgyEoRIShBh1loFxRVgAAAFxNgmxTAAABAMARjBEAiA7PNq+MFfv6O9mBkxFViS2TfU66yRB" +
    "/njcebWglLQjZQIgOyRKhxlEizncFRml7yn4Bg48ktXKGjo+uiw6zXEINb0wDQYJKoZIhvcN" +
    "AQELBQADggEBADM2Rh306Q10PScsolYMxH1B/K4Nb2WICvpY0yDPJFdnGjqCYym196TjiEvs" +
    "R6etfeHdyzlZj6nh82B4TVyHjiWM02dQgPalOuWQcuSy0OvLh7F1E7CeHzKlczdFPBTOTdM1" +
    "RDTxlvw1bAqc0zueM8QIAyEy3opd7FxAcGQd5WRIJhzLBL+dbbMOW/LTeW7cm/Xzq8cgCybN" +
    "BSZAvhjseJ1L29OlCTZL97IfnX0IlFQzWuvvHy7V2B0E3DHlzM0kjwkkCKDUUp/wajv2NZKC" +
    "TkhEyERacZRKc9U0ADxwsAzHrdz5+5zfD2usEV/MQ5V6d8swLXs+ko0X6swrd4YCiB8wggRK" +
    "MIIDMqADAgECAg0B47SaoY2KqYElaVC4MA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0ds" +
    "b2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH" +
    "bG9iYWxTaWduMB4XDTE3MDYxNTAwMDA0MloXDTIxMTIxNTAwMDA0MlowQjELMAkGA1UEBhMC" +
    "VVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczETMBEGA1UEAxMKR1RTIENBIDFP" +
    "MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAYz0XUi83TnORA73603WkhG8nP" +
    "PI5MdbkPMRmEPZ48Ke9QDRCTbwWAgJ8qoL0SSwLhPZ9YFiT+MJ8LdHdVkx1L903hkoIQ9lGs" +
    "DMOyIpQPNGuYEEnnC52DOd0gxhwt79EYYWXnI4MgqCMS/9Ikf9Qv50RqW03XUGawr55CYwX7" +
    "4BzEY2Gvn2oz/2KXvUjZ03wUZ9x13C5p6PhteGnQtxAFuPExwjsk/RozdPgj4OxrGYoWxuPN" +
    "pM0L27OkWWA4iDutHbnGjKdTG/y82aSrvN08YdeTFZjugb2P4mRHIEAGTtesl+i5wFkSoUkl" +
    "I+TtcDQspbRjfPmjPYPRzW0krAcCAwEAAaOCATMwggEvMA4GA1UdDwEB/wQEAwIBhjAdBgNV" +
    "HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E" +
    "FgQUmNH4bhDrz5vsYJ8YkBug630J/SswHwYDVR0jBBgwFoAUm+IHV2ccHsBqBt5ZtJot39wZ" +
    "hi4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5wa2kuZ29vZy9n" +
    "c3IyMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMi9nc3IyLmNy" +
    "bDA/BgNVHSAEODA2MDQGBmeBDAECAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3BraS5nb29n" +
    "L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAagD42efvzLqlGN31eVBY1rsdOCJn+" +
    "vdE0aSZSZgc9CrpJy2L08RqO/BFPaJZMdCvTZ96yo6oFjYRNTCBlD6WW2g0W+Gw7228EI4hr" +
    "OmzBYL1on3GO7i1YNAfw1VTphln9e14NIZT1jMmo+NjyrcwPGvOap6kEJ/mjybD/AnhrYbrH" +
    "NSvoVvpPwxwM7bY8tEvq7czhPOzcDYzWPpvKQliLzBYhF0C8otZm79rEFVvNiaqbCSbnMtIN" +
    "bmcgAlsQsJAJnAwfnq3YO+qh/GzoEFwIUhlRKnG7rHq13RXtK8kIKiyKtKYhq2P/11JJUNCJ" +
    "t63yr/tQri/hlQ3zRq2dnPXK"

func TestCertificateParse(t *testing.T) {
    s, _ := base64.StdEncoding.DecodeString(certBytes)
    certs, err := ParseCertificates(s)
    if err != nil {
        t.Error(err)
    }

    if len(certs) != 2 {
        t.Errorf("Wrong number of certs: got %d want 2", len(certs))
        return
    }

    err = certs[0].CheckSignatureFrom(certs[1])
    if err != nil {
        t.Error(err)
    }

    if err := certs[0].VerifyHostname("mail.google.com"); err != nil {
        t.Error(err)
    }

    const expectedExtensions = 10
    if n := len(certs[0].Extensions); n != expectedExtensions {
        t.Errorf("want %d extensions, got %d", expectedExtensions, n)
    }
}
