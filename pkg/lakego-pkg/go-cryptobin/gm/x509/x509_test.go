package x509

import (
    "fmt"
    "net"
    "time"
    "testing"
    "math/big"
    "encoding/asn1"
    "crypto/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

func TestX509(t *testing.T) {
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
    } else {
        fmt.Printf("CheckSignature ok\n")
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
    } else {
        fmt.Printf("CheckSignature ok\n")
    }
}
