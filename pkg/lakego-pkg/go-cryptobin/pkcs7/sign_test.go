package pkcs7

import (
    "os"
    "os/exec"
    "fmt"
    "bytes"
    "testing"
    "io/ioutil"
    "encoding/asn1"

    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
)

type testSignOid struct{
    sa cryptobin_x509.SignatureAlgorithm
    eoid asn1.ObjectIdentifier
}

func testSign(t *testing.T, isSM bool, content []byte, sigalgs []testSignOid) {
    for _, sigalg := range sigalgs {
        sigalgroot := sigalg.sa

        rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
        if err != nil {
            t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
        }

        truststore := cryptobin_x509.NewCertPool()
        truststore.AddCert(rootCert.Certificate)

        for _, sigalginter1 := range sigalgs {
            sigalginter := sigalginter1.sa

            interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
            if err != nil {
                t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
            }

            var parents []*cryptobin_x509.Certificate
            parents = append(parents, interCert.Certificate)

            for _, sigalgsigner1 := range sigalgs {
                sigalgsigner := sigalgsigner1.sa

                signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
                if err != nil {
                    t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
                }

                for _, testDetach := range []bool{false, true} {
                    var toBeSigned *SignedData
                    if isSM {
                        toBeSigned, err = NewSMSignedData(content)
                    } else {
                        toBeSigned, err = NewSignedData(content)
                    }
                    if err != nil {
                        t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
                    }

                    // Set the digest to match the end entity cert
                    signerDigest, _ := getDigestOIDForSignatureAlgorithm(sigalgsigner)
                    toBeSigned.SetDigestAlgorithm(signerDigest)
                    toBeSigned.SetEncryptionAlgorithm(sigalgsigner1.eoid)

                    if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
                        t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
                    }

                    if testDetach {
                        toBeSigned.Detach()
                    }

                    signed, err := toBeSigned.Finish()
                    if err != nil {
                        t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
                    }

                    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

                    p7, err := Parse(signed)
                    if err != nil {
                        t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
                    }

                    if testDetach {
                        p7.Content = content
                    }

                    if !bytes.Equal(content, p7.Content) {
                        t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
                    }

                    if err := p7.VerifyWithChain(truststore); err != nil {
                        t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
                    }

                    if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
                        t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
                            sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
                    }
                }
            }
        }
    }
}

func TestSign(t *testing.T) {
    content := []byte("Hello World")
    sigalgs := []testSignOid{
        {
            cryptobin_x509.SHA1WithRSA,
            OidEncryptionAlgorithmRSASHA1,
        },
        {
            cryptobin_x509.SHA256WithRSA,
            OidEncryptionAlgorithmRSASHA256,
        },
        {
            cryptobin_x509.SHA512WithRSA,
            OidEncryptionAlgorithmRSASHA512,
        },

        {
            cryptobin_x509.ECDSAWithSHA1,
            OidEncryptionAlgorithmECDSASHA1,
        },
        {
            cryptobin_x509.ECDSAWithSHA256,
            OidEncryptionAlgorithmECDSASHA256,
        },
        {
            cryptobin_x509.ECDSAWithSHA384,
            OidEncryptionAlgorithmECDSASHA384,
        },
        {
            cryptobin_x509.ECDSAWithSHA512,
            OidEncryptionAlgorithmECDSASHA512,
        },

        /*
        {
            cryptobin_x509.SM2WithSM3,
            OidDigestEncryptionAlgorithmSM2,
        },
        */
    }

    testSign(t, false, content, sigalgs)
}

func testSignSM(t *testing.T) {
    content := []byte("Hello World")
    sigalgs := []testSignOid{
        {
            cryptobin_x509.SM2WithSM3,
            OidDigestEncryptionAlgorithmSM2,
        },
    }

    testSign(t, true, content, sigalgs)
}

func ExampleSignedData() {
    // generate a signing cert or load a key pair
    cert, err := createTestCertificate(cryptobin_x509.SHA256WithRSA)
    if err != nil {
        fmt.Printf("Cannot create test certificates: %s", err)
    }

    // Initialize a SignedData struct with content to be signed
    signedData, err := NewSignedData([]byte("Example data to be signed"))
    if err != nil {
        fmt.Printf("Cannot initialize signed data: %s", err)
    }

    // Add the signing cert and private key
    if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
        fmt.Printf("Cannot add signer: %s", err)
    }

    // Call Detach() is you want to remove content from the signature
    // and generate an S/MIME detached signature
    signedData.Detach()

    // Finish() to obtain the signature bytes
    detachedSignature, err := signedData.Finish()
    if err != nil {
        fmt.Printf("Cannot finish signing data: %s", err)
    }

    if len(detachedSignature) == 0 {
        fmt.Println("Cannot finish signing data: Finish fail")
    }

    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestUnmarshalSignedAttribute(t *testing.T) {
    cert, err := createTestCertificate(cryptobin_x509.SHA512WithRSA)
    if err != nil {
        t.Fatal(err)
    }
    content := []byte("Hello World")
    toBeSigned, err := NewSignedData(content)
    if err != nil {
        t.Fatalf("Cannot initialize signed data: %s", err)
    }
    oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
    testValue := "TestValue"
    if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
        ExtraSignedAttributes: []Attribute{{Type: oidTest, Value: testValue}},
    }); err != nil {
        t.Fatalf("Cannot add signer: %s", err)
    }
    signed, err := toBeSigned.Finish()
    if err != nil {
        t.Fatalf("Cannot finish signing data: %s", err)
    }
    p7, err := Parse(signed)
    if err != nil {
        t.Fatalf("Cannot parse signed data: %v", err)
    }
    var actual string
    err = p7.UnmarshalSignedAttribute(oidTest, &actual)
    if err != nil {
        t.Fatalf("Cannot unmarshal test value: %s", err)
    }
    if testValue != actual {
        t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
    }
    err = p7.Verify()
    if err != nil {
        t.Fatal(err)
    }
}

func TestSkipCertificates(t *testing.T) {
    cert, err := createTestCertificate(cryptobin_x509.SHA512WithRSA)
    if err != nil {
        t.Fatal(err)
    }
    content := []byte("Hello World")
    toBeSigned, err := NewSignedData(content)
    if err != nil {
        t.Fatalf("Cannot initialize signed data: %s", err)
    }

    if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
        t.Fatalf("Cannot add signer: %s", err)
    }
    signed, err := toBeSigned.Finish()
    if err != nil {
        t.Fatalf("Cannot finish signing data: %s", err)
    }
    p7, err := Parse(signed)
    if err != nil {
        t.Fatalf("Cannot parse signed data: %v", err)
    }
    if len(p7.Certificates) == 0 {
        t.Errorf("No certificates")
    }

    toBeSigned2, err := NewSignedData(content)
    if err != nil {
        t.Fatalf("Cannot initialize signed data: %s", err)
    }
    if err := toBeSigned2.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{SkipCertificates: true}); err != nil {
        t.Fatalf("Cannot add signer: %s", err)
    }
    signed, err = toBeSigned2.Finish()
    if err != nil {
        t.Fatalf("Cannot finish signing data: %s", err)
    }
    p7, err = Parse(signed)
    if err != nil {
        t.Fatalf("Cannot parse signed data: %v", err)
    }
    if len(p7.Certificates) > 0 {
        t.Errorf("Have certificates: %v", p7.Certificates)
    }
}

func TestDegenerateCertificate(t *testing.T) {
    cert, err := createTestCertificate(cryptobin_x509.SHA1WithRSA)
    if err != nil {
        t.Fatal(err)
    }
    deg, err := DegenerateCertificate(cert.Certificate.Raw)
    if err != nil {
        t.Fatal(err)
    }

    if len(deg) == 0 {
        t.Error("DegenerateCertificate fail")
    }

    // testOpenSSLParse(t, deg)

    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
    tmpCertFile, err := ioutil.TempFile("", "testCertificate")
    if err != nil {
        t.Fatal(err)
    }
    defer os.Remove(tmpCertFile.Name()) // clean up

    if _, err := tmpCertFile.Write(certBytes); err != nil {
        t.Fatal(err)
    }

    opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
    _, err = opensslCMD.Output()
    if err != nil {
        t.Fatal(err)
    }

    if err := tmpCertFile.Close(); err != nil {
        t.Fatal(err)
    }
}

func TestSignWithoutAttr(t *testing.T) {
    content := []byte("Hello World")
    sigalgs := []struct {
        isSM   bool
        sigAlg cryptobin_x509.SignatureAlgorithm
    }{
        {
            false,
            cryptobin_x509.SHA256WithRSA,
        },
        {
            true,
            cryptobin_x509.SM2WithSM3,
        },
    }

    for i, sigalg := range sigalgs {
        cert, err := createTestCertificate(sigalg.sigAlg)
        if err != nil {
            t.Fatal(err)
        }

        var toBeSigned *SignedData
        if sigalg.isSM {
            toBeSigned, err = NewSMSignedData(content)
        } else {
            toBeSigned, err = NewSignedData(content)
            signerDigest, _ := getDigestOIDForSignatureAlgorithm(sigalg.sigAlg)
            toBeSigned.SetDigestAlgorithm(signerDigest)
        }

        if err != nil {
            t.Fatalf("[%d] Cannot initialize signed data: %s", i, err)
        }

        if err := toBeSigned.SignWithoutAttr(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
            t.Fatalf("[%d] Cannot add signer: %s", i, err)
        }

        signed, err := toBeSigned.Finish()
        if err != nil {
            t.Fatalf("[%d] Cannot finish signing data: %s", i, err)
        }
        p7, err := Parse(signed)
        if err != nil {
            t.Fatalf("[%d] Cannot parse signed data: %v", i, err)
        }

        if len(p7.Certificates) == 0 {
            t.Errorf("[%d] No certificates", i)
        }

        err = p7.Verify()
        if err != nil {
            t.Fatal(err)
        }
    }
}
