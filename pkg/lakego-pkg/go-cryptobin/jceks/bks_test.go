package jceks

import (
    "testing"
    "crypto/rsa"
    "crypto/x509"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_BksEncode(t *testing.T) {
    test_BksEncode(t, 1)
    test_BksEncode(t, 2)
}

func test_BksEncode(t *testing.T, ver int) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertNoError(err, "BksEncode-caCerts")

    cert, err := x509.ParseCertificate(decodePEM(certificate))
    assertNoError(err, "BksEncode-cert")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertNoError(err, "BksEncode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("BksEncode rsa Error")
    }

    publicKey := &privateKey.PublicKey

    password := "12345678"

    secretKey := []byte("sealed_secret_key-data")
    storedValue := []byte("stored_value-data")
    plainKey := []byte("plain_key-data")

    en := NewBksEncode()

    en.AddCert("cert-test", cert, nil);
    en.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, caCerts);
    en.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    en.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);
    en.AddSecret("stored_value", storedValue, nil);
    en.AddKeySecret("plain_key", plainKey, "AES", nil);
    en.AddKeyPrivate("private_key", privateKey, caCerts);
    en.AddKeyPublic("public_key", publicKey, nil);

    opts := BKSOpts{
        Version:        ver,
        SaltSize:       20,
        IterationCount: 10000,
    }

    pfxData, err := en.Marshal(password, opts)

    assertNoError(err, "BksEncode Marshal Error")
    assertNotEmpty(pfxData, "BksEncode-pfxData")

    // ========

    ks, err := LoadBksFromBytes(pfxData, password)
    assertNoError(err, "BksEncode-DE")

    certsAliases := ks.ListCerts()
    assertNotEmpty(certsAliases, "BksEncode-ListCerts")

    secretsAliases := ks.ListSecrets()
    assertNotEmpty(secretsAliases, "BksEncode-secretsAliases")

    keysAliases := ks.ListKeys()
    assertNotEmpty(keysAliases, "BksEncode-keysAliases")

    sealedKeysAliases := ks.ListSealedKeys()
    assertNotEmpty(sealedKeysAliases, "BksEncode-sealedKeysAliases")

    version := ks.Version()
    assertNotEmpty(version, "BksEncode-version")
    assertEqual(int(version), ver, "BksEncode-GetSecret")

    storeType := ks.StoreType()
    assertNotEmpty(storeType, "BksEncode-StoreType")
    assertEqual(storeType, "bks", "BksEncode-StoreType")

    date, err := ks.GetCreateDate("sealed_private_key")
    assertNoError(err, "BksEncode-sealed_private_key-date")
    assertNotEmpty(date, "BksEncode-sealed_private_key-date")

    cert2, err := ks.GetCert("cert-test")
    assertNoError(err, "BksEncode-GetCert")
    assertNotEmpty(cert2, "BksEncode-GetCert")
    assertEqual(cert2, cert, "BksEncode-GetCert")

    secret, err := ks.GetSecret("stored_value")
    assertNoError(err, "BksEncode-GetSecret")
    assertNotEmpty(secret, "BksEncode-GetSecret")
    assertEqual(secret, storedValue, "BksEncode-GetSecret")

    plainKey2, err := ks.GetKeySecret("plain_key")
    assertNoError(err, "BksEncode-GetKeySecret")
    assertNotEmpty(plainKey2, "BksEncode-GetKeySecret")
    assertEqual(plainKey2, plainKey, "BksEncode-GetKeySecret")

    privateKey2, err := ks.GetKeyPrivateWithPassword("sealed_private_key", password)
    assertNoError(err, "BksEncode-GetKeyPrivateWithPassword")
    assertNotEmpty(privateKey2, "BksEncode-GetKeyPrivateWithPassword")
    assertEqual(privateKey2, privateKey, "BksEncode-GetKeyPrivateWithPassword")

    publicKey2, err := ks.GetKeyPublicWithPassword("sealed_public_key", password)
    assertNoError(err, "BksEncode-GetKeyPublicWithPassword")
    assertNotEmpty(publicKey2, "BksEncode-GetKeyPublicWithPassword")
    assertEqual(publicKey2, publicKey, "BksEncode-GetKeyPublicWithPassword")

    secret2, err := ks.GetKeySecretWithPassword("sealed_secret_key", password)
    assertNoError(err, "BksEncode-GetKeyPublicWithPassword")
    assertNotEmpty(secret2, "BksEncode-GetKeyPublicWithPassword")
    assertEqual(secret2, secretKey, "BksEncode-GetKeyPublicWithPassword")

    certChain, err := ks.GetCertChain("sealed_private_key")
    assertNoError(err, "BksEncode-GetCertChain-sealed_private_key")
    assertNotEmpty(certChain, "BksEncode-GetCertChain-sealed_private_key")
    assertEqual(certChain, caCerts, "BksEncode-GetCertChain-sealed_private_key")

    privateKey3, err := ks.GetKeyPrivate("private_key")
    assertNoError(err, "BksEncode-GetKeyPrivate")
    assertNotEmpty(privateKey3, "BksEncode-GetKeyPrivate")
    assertEqual(privateKey3, privateKey, "BksEncode-GetKeyPrivate")

    publicKey3, err := ks.GetKeyPublic("public_key")
    assertNoError(err, "BksEncode-GetKeyPublic")
    assertNotEmpty(publicKey3, "BksEncode-GetKeyPublic")
    assertEqual(publicKey3, publicKey, "BksEncode-GetKeyPublic")

    certChain3, err := ks.GetCertChain("private_key")
    assertNoError(err, "BksEncode-GetCertChain-private_key")
    assertNotEmpty(certChain3, "BksEncode-GetCertChain-private_key")
    assertEqual(certChain3, caCerts, "BksEncode-GetCertChain-private_key")
}

func Test_UberEncode(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertNoError(err, "UberEncode-caCerts")

    cert, err := x509.ParseCertificate(decodePEM(certificate))
    assertNoError(err, "UberEncode-cert")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertNoError(err, "UberEncode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("UberEncode rsa Error")
    }

    publicKey := &privateKey.PublicKey

    password := "12345678"

    secretKey := []byte("sealed_secret_key-data")
    storedValue := []byte("stored_value-data")
    plainKey := []byte("plain_key-data")

    en := NewUberEncode()

    en.AddCert("cert-test", cert, nil);
    en.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, caCerts);
    en.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    en.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);
    en.AddSecret("stored_value", storedValue, nil);
    en.AddKeySecret("plain_key", plainKey, "AES", nil);
    en.AddKeyPrivate("private_key", privateKey, caCerts);
    en.AddKeyPublic("public_key", publicKey, nil);

    opts := UBEROpts{
        SaltSize:       20,
        IterationCount: 10000,
    }

    pfxData, err := en.Marshal(password, opts)

    assertNoError(err, "UberEncode Marshal Error")
    assertNotEmpty(pfxData, "UberEncode-pfxData")

    // ========

    ks, err := LoadUberFromBytes(pfxData, password)
    assertNoError(err, "UberEncode-DE")

    certsAliases := ks.ListCerts()
    assertNotEmpty(certsAliases, "UberEncode-ListCerts")

    secretsAliases := ks.ListSecrets()
    assertNotEmpty(secretsAliases, "UberEncode-secretsAliases")

    keysAliases := ks.ListKeys()
    assertNotEmpty(keysAliases, "UberEncode-keysAliases")

    sealedKeysAliases := ks.ListSealedKeys()
    assertNotEmpty(sealedKeysAliases, "UberEncode-sealedKeysAliases")

    version := ks.Version()
    assertNotEmpty(version, "UberEncode-version")
    assertEqual(int(version), 1, "UberEncode-GetSecret")

    storeType := ks.StoreType()
    assertNotEmpty(storeType, "UberEncode-StoreType")
    assertEqual(storeType, "uber", "UberEncode-StoreType")

    date, err := ks.GetCreateDate("sealed_private_key")
    assertNoError(err, "UberEncode-sealed_private_key-date")
    assertNotEmpty(date, "UberEncode-sealed_private_key-date")

    cert2, err := ks.GetCert("cert-test")
    assertNoError(err, "UberEncode-GetCert")
    assertNotEmpty(cert2, "UberEncode-GetCert")
    assertEqual(cert2, cert, "UberEncode-GetCert")

    secret, err := ks.GetSecret("stored_value")
    assertNoError(err, "UberEncode-GetSecret")
    assertNotEmpty(secret, "UberEncode-GetSecret")
    assertEqual(secret, storedValue, "UberEncode-GetSecret")

    plainKey2, err := ks.GetKeySecret("plain_key")
    assertNoError(err, "UberEncode-GetKeySecret")
    assertNotEmpty(plainKey2, "UberEncode-GetKeySecret")
    assertEqual(plainKey2, plainKey, "UberEncode-GetKeySecret")

    privateKey2, err := ks.GetKeyPrivateWithPassword("sealed_private_key", password)
    assertNoError(err, "UberEncode-GetKeyPrivateWithPassword")
    assertNotEmpty(privateKey2, "UberEncode-GetKeyPrivateWithPassword")
    assertEqual(privateKey2, privateKey, "UberEncode-GetKeyPrivateWithPassword")

    publicKey2, err := ks.GetKeyPublicWithPassword("sealed_public_key", password)
    assertNoError(err, "UberEncode-GetKeyPublicWithPassword")
    assertNotEmpty(publicKey2, "UberEncode-GetKeyPublicWithPassword")
    assertEqual(publicKey2, publicKey, "UberEncode-GetKeyPublicWithPassword")

    secret2, err := ks.GetKeySecretWithPassword("sealed_secret_key", password)
    assertNoError(err, "UberEncode-GetKeyPublicWithPassword")
    assertNotEmpty(secret2, "UberEncode-GetKeyPublicWithPassword")
    assertEqual(secret2, secretKey, "UberEncode-GetKeyPublicWithPassword")

    certChain, err := ks.GetCertChain("sealed_private_key")
    assertNoError(err, "UberEncode-GetCertChain-sealed_private_key")
    assertNotEmpty(certChain, "UberEncode-GetCertChain-sealed_private_key")
    assertEqual(certChain, caCerts, "UberEncode-GetCertChain-sealed_private_key")

    privateKey3, err := ks.GetKeyPrivate("private_key")
    assertNoError(err, "UberEncode-GetKeyPrivate")
    assertNotEmpty(privateKey3, "UberEncode-GetKeyPrivate")
    assertEqual(privateKey3, privateKey, "UberEncode-GetKeyPrivate")

    publicKey3, err := ks.GetKeyPublic("public_key")
    assertNoError(err, "UberEncode-GetKeyPublic")
    assertNotEmpty(publicKey3, "UberEncode-GetKeyPublic")
    assertEqual(publicKey3, publicKey, "UberEncode-GetKeyPublic")

    certChain3, err := ks.GetCertChain("private_key")
    assertNoError(err, "UberEncode-GetCertChain-private_key")
    assertNotEmpty(certChain3, "UberEncode-GetCertChain-private_key")
    assertEqual(certChain3, caCerts, "UberEncode-GetCertChain-private_key")
}
