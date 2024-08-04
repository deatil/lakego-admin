package x509_test

import (
    "fmt"
    "time"
    "testing"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/x509/pkix"
    "encoding/hex"

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

    // Marshal sign certificate only
    result, err = x509.MarshalCSRResponse([]*x509.Certificate{pairs[0].Certificate, pairs[2].Certificate}, nil, nil)
    if err != nil {
        t.Errorf("Unexpected error: %v", err)
    }

    resp, err = x509.ParseCSRResponse(signPrivKey, result)
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

func Test_MarshalSM2EnvelopedPrivateKey(t *testing.T) {
    priv, _ := sm2.GenerateKey(rand.Reader)
    toEnveloped, _ := sm2.GenerateKey(rand.Reader)

    result, err := x509.MarshalSM2EnvelopedPrivateKey(rand.Reader, &priv.PublicKey, toEnveloped)
    if err != nil {
        t.Fatal(err)
    }

    parsedKey, err := x509.ParseSM2EnvelopedPrivateKey(priv, result)
    if err != nil {
        t.Fatal(err)
    }

    if !toEnveloped.Equal(parsedKey) {
        t.Error("Marshal Enveloped PrivateKey error")
    }
}

func Test_MarshalSM2EnvelopedPrivateKeyWithSM4CBC(t *testing.T) {
    priv, _ := sm2.GenerateKey(rand.Reader)
    toEnveloped, _ := sm2.GenerateKey(rand.Reader)

    result, err := x509.MarshalSM2EnvelopedPrivateKey(rand.Reader, &priv.PublicKey, toEnveloped, x509.EnvelopedOpts{
        Cipher: x509.Enveloped_SM4CBC,
    })
    if err != nil {
        t.Fatal(err)
    }

    parsedKey, err := x509.ParseSM2EnvelopedPrivateKey(priv, result)
    if err != nil {
        t.Fatal(err)
    }

    if !toEnveloped.Equal(parsedKey) {
        t.Error("Marshal Enveloped PrivateKey error")
    }
}

func Test_ParseEnvelopedPrivateKey(t *testing.T) {
    key, _ := hex.DecodeString("5cbd96822bb1491ec835ae9c09d4d3825e30bd9955e3c7031fbbe0e72d6fddf6")
    sm2Key := new(sm2.PrivateKey)
    sm2Key.D = new(big.Int).SetBytes(key)
    sm2Key.Curve = sm2.P256()
    sm2Key.X, sm2Key.Y = sm2Key.ScalarBaseMult(key)

    invalidASN1, _ := hex.DecodeString("3081ea06082a811ccf550168013079022003858a7ca681c2e7034804d2bcece2d1c200e128ca973f3ad12541b59ec639cd022100bcf5834c775d5d43615abc27d3aeee399985d30942c65cdbe95afc87d96b12860420f84efafe256413fb28af65a57d815cb9a2fc64f754ab29adc1a78e81c433cfe90410fd485762e9c5714a6ee008e76675a14c0441049355f3009f1db15d6a6f751531f3c4741a36a43d1146fc1b0f660314e5fc3b825ed2fda18cb2f624ac6afb370b3755bb267b5747dd8f15836c830b52d4a74d2c04206fd2ef53be43aaa7f0440e96aafd846096f993e254e2a79a9a5b583204487183")
    if _, err := x509.ParseSM2EnvelopedPrivateKey(sm2Key, invalidASN1); err.Error() != "x509: invalid asn1 format enveloped key" {
        t.Errorf("expected asn1 error, got %s", err)
    }

    invalidOID, _ := hex.DecodeString("3081ef300c06082a811ccf55016802050030780220760c5d4eb80f7ec4bb12026586e4badcd41c293b416618575894d9278214aa6c02203fea869801f94f1cf3839e9b666482703c86cef160af8a540daf9c6b9adff5b20420685f05616055daf4948e44d76c366b16745f7a487614c0542d16871baa34be8704104abfcab6cea65caf2c130b222ebe519903420004944a5887f6fad9808516755e81c62f41566dab0f56ca55ad7909880acc051ce157694b11557eba725291166508868e6988c596a30472bef32e03a3dcef6866270321003ec6b59fece00ca37336c12f6d529aa84be07597e315eda1b7b58b0bef2fead9")
    if _, err := x509.ParseSM2EnvelopedPrivateKey(sm2Key, invalidOID); err.Error() != "pkcs/cipher: invalid iv parameters" {
        t.Errorf("expected invalid oid error, got %s", err)
    }

    decryptErr, _ := hex.DecodeString("308183300c06082a811ccf550168010500300c06082a811ccf55016801050003420004cb51edb59a99b3b6bc894f203465bf04045eb8a85f5a14ba7c894aadbba7f7b5093e568351675d4ffd6d90be77ae182656eb98a80289358cd4ad4d65fafec5dc03210074bd8d993eeeb0220a664087b80478c43ddf322dd75e16db1642f5938ca34a0c")
    if _, err := x509.ParseSM2EnvelopedPrivateKey(sm2Key, decryptErr); err.Error() != "x509: invalid asn1 format enveloped key" {
        t.Errorf("expected decrypt error, got %s", err)
    }
}
