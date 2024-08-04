package x509_test

import (
    "fmt"
    "time"
    "testing"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

type certKeyPair struct {
    Certificate *x509.Certificate
    PrivateKey  *crypto.PrivateKey
}

func createTestCertificate() ([]*certKeyPair, error) {
    signer, err := createTestCertificateByIssuer("Test CA", nil, true)
    if err != nil {
        return nil, err
    }
    pair1, err := createTestCertificateByIssuer("Test Org Sign", signer, false)
    if err != nil {
        return nil, err
    }
    pair2, err := createTestCertificateByIssuer("Test Org Enc", signer, false)
    if err != nil {
        return nil, err
    }
    return []*certKeyPair{pair1, pair2, signer}, nil
}

func createTestCertificateByIssuer(name string, issuer *certKeyPair, isCA bool) (*certKeyPair, error) {
    var (
        err        error
        priv       crypto.PrivateKey
        derCert    []byte
        issuerCert *x509.Certificate
        issuerKey  crypto.PrivateKey
    )
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return nil, err
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   name,
            Organization: []string{"Acme Co"},
        },
        NotBefore:   time.Now().Add(-1 * time.Second),
        NotAfter:    time.Now().AddDate(1, 0, 0),
        KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
    }
    if issuer != nil {
        issuerCert = issuer.Certificate
        issuerKey = *issuer.PrivateKey
    }

    priv, err = sm2.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }

    pkey := priv.(crypto.Signer)
    if isCA {
        template.IsCA = true
        template.KeyUsage |= x509.KeyUsageCertSign
        template.BasicConstraintsValid = true
    }
    if issuer == nil {
        // no issuer given,make this a self-signed root cert
        issuerCert = (*x509.Certificate)(&template)
        issuerKey = priv
    }

    derCert, err = x509.CreateCertificate(rand.Reader, &template, (*x509.Certificate)(issuerCert), pkey.Public(), issuerKey)
    if err != nil {
        return nil, err
    }
    if len(derCert) == 0 {
        return nil, fmt.Errorf("no certificate created, probably due to wrong keys. types were %T and %T", priv, issuerKey)
    }
    cert, err := x509.ParseCertificate(derCert)
    if err != nil {
        return nil, err
    }

    return &certKeyPair{
        Certificate: cert,
        PrivateKey:  &priv,
    }, nil
}

func Test_MarshalCSRResponse(t *testing.T) {
    pairs, err := createTestCertificate()
    if err != nil {
        t.Fatal(err)
    }

    signPrivKey, _ := (*pairs[0].PrivateKey).(*sm2.PrivateKey)
    encPrivKey, _ := (*pairs[1].PrivateKey).(*sm2.PrivateKey)

    {
        result, err := x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, encPrivKey, []*x509.Certificate{pairs[1].Certificate, pairs[2].Certificate})
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }

        resp, err := x509.ParseCSRResponse(signPrivKey, result)
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }
        if len(resp.SignCerts) != 2 {
            t.Errorf("Unexpected number of sign certs: %d", len(resp.SignCerts))
        }
        if resp.EncryptPrivateKey == nil || !encPrivKey.Equal(resp.EncryptPrivateKey) {
            t.Errorf("Unexpected encrypt private key")
        }
        if len(resp.EncryptCerts) != 2 {
            t.Errorf("Unexpected number of encrypt certs: %d", len(resp.EncryptCerts))
        }
    }

    // use some modes
    {
        result, err := x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, encPrivKey, []*x509.Certificate{pairs[1].Certificate, pairs[2].Certificate}, x509.EnvelopedOpts{
            Cipher: x509.Enveloped_SM4CBC,
        })
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }

        resp, err := x509.ParseCSRResponse(signPrivKey, result)
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }
        if len(resp.SignCerts) != 2 {
            t.Errorf("Unexpected number of sign certs: %d", len(resp.SignCerts))
        }
        if resp.EncryptPrivateKey == nil || !encPrivKey.Equal(resp.EncryptPrivateKey) {
            t.Errorf("Unexpected encrypt private key")
        }
        if len(resp.EncryptCerts) != 2 {
            t.Errorf("Unexpected number of encrypt certs: %d", len(resp.EncryptCerts))
        }
    }

    {
        // Marshal sign certificate only
        result, err := x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, nil, nil)
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }

        resp, err := x509.ParseCSRResponse(signPrivKey, result)
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
        }
        if len(resp.SignCerts) != 2 {
            t.Errorf("Unexpected number of sign certs: %d", len(resp.SignCerts))
        }
        if resp.EncryptPrivateKey != nil {
            t.Errorf("Unexpected encrypt private key")
        }
        if resp.EncryptCerts != nil {
            t.Errorf("Unexpected encrypt certs")
        }
    }

    _, err = x509.MarshalCSRResponse(nil, nil, nil)
    if err == nil || err.Error() != "x509: no sign certificate" {
        t.Errorf("Unexpected error: %v", err)
    }

    _, err = x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, encPrivKey, nil)
    if err == nil || err.Error() != "x509: missing encrypt certificate" {
        t.Errorf("Unexpected error: %v", err)
    }

    _, err = x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, encPrivKey, []*x509.Certificate{pairs[2].Certificate})
    if err == nil || err.Error() != "x509: encrypt key pair mismatch" {
        t.Errorf("Unexpected error: %v", err)
    }
}
