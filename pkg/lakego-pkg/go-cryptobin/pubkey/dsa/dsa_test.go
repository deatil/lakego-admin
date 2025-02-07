package dsa

import (
    "testing"
    "crypto/dsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/pem"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func test_GenerateKey() *dsa.PrivateKey {
    priv := &dsa.PrivateKey{}
    dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160)
    dsa.GenerateKey(priv, rand.Reader)

    return priv
}

func Test_MarshalPKCS1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey()
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS1")

    //===============

    pubDer, err := MarshalPKCS1PublicKey(pub)
    assertNoError(err, "MarshalPKCS1-pub-Error")
    assertNotEmpty(pubDer, "MarshalPKCS1")

    parsedPub, err := ParsePKCS1PublicKey(pubDer)
    assertNoError(err, "MarshalPKCS1-pub-Error")
    assertEqual(pub, parsedPub, "MarshalPKCS1")

    //===============

    priDer, err := MarshalPKCS1PrivateKey(pri)
    assertNoError(err, "MarshalPKCS1-pri-Error")
    assertNotEmpty(priDer, "MarshalPKCS1")

    parsedPri, err := ParsePKCS1PrivateKey(priDer)
    assertNoError(err, "MarshalPKCS1-pri-Error")
    assertEqual(pri, parsedPri, "MarshalPKCS1")
}

func Test_MarshalPKCS8(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey()
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS8")

    //===============

    pubDer, err := MarshalPKCS8PublicKey(pub)
    assertNoError(err, "MarshalPKCS8PublicKey-pub-Error")
    assertNotEmpty(pubDer, "MarshalPKCS8PublicKey")

    parsedPub, err := ParsePKCS8PublicKey(pubDer)
    assertNoError(err, "ParsePKCS8PublicKey-pub-Error")
    assertEqual(parsedPub, pub, "MarshalPKCS8")

    //===============

    priDer, err := MarshalPKCS8PrivateKey(pri)
    assertNoError(err, "MarshalPKCS8PrivateKey-pri-Error")
    assertNotEmpty(priDer, "MarshalPKCS8PrivateKey")

    parsedPri, err := ParsePKCS8PrivateKey(priDer)
    assertNoError(err, "ParsePKCS8PrivateKey-pri-Error")
    assertEqual(parsedPri, pri, "ParsePKCS8PrivateKey")
}

// botan keygen --algo=DSA | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
var privPKCS8PEM = `-----BEGIN PRIVATE KEY-----
MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCRxIpP37z3wCrpXn2hJhIrXdKG
T1Wbh+jnSihtUvWb0d5o39ZF0OAMYMCAAxiRmAN07rWUpTK/1nuaCerEuGY6B5EO
aPOUZftwQNJd8Tky66xDR6Uw7LphyFT5uIDTwMNmAIBYfEVWba3ia9WjlL4JO0wP
JLWv/vjsbFs+V/uJAlqbwWdpkyEx4W08lO/KsY0N8GEgPMU+YQO8ctVZS/1AymU4
D0SpqFHcsHVJX8AzqKWAcaG9eP4FL2ZVVkjrS3GdKv6LSID42tbxWBi6F4+JJ0yH
C+m5brCMRsQAQMwu/h37Gxho3TGd48NKMqY6tusSJCCaQZaAzHkC0XKNTfnhAiEA
jNfUUPhvCtlO7kzkaah1bR69EFgkGUPq/7CzVFhekk0CggEADZ9eB2G029GDPWqx
qWGgmWxfIjA/cthMFA9nxDHZSrVxW+qBoMmNOc5Lz3jWuevIldNP6J2UCR1YSGFe
8V9ehvEdlvbJaeID3fpYNWQgpJy0RLWVuQGpM8/gdntZTxige3+R3s26RGuImQ94
8v+R8v581D/S5G0Y6tofe7ZgLGF/bvOksoTy/ZuhCjYELej6h6LKNll/7IEVehSF
5EBB3wKDARHLiAu+btSUgUiG+WXNwxNfXM8Tg3KL9luAb5aSwLENbEwJx1pso7QB
PLFqssEF9r4jrqkADqsheJhflyyYBX4chuROchhojqSuDzY23Mp0XJ3NTmr/tnzL
wT1hMQQiAiBR7MZNy4MxFz756btisPcLMXIP6gKHDGsrV20L3IEkuA==
-----END PRIVATE KEY-----
`
var pubPKCS8PEM = `-----BEGIN PUBLIC KEY-----
MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQCRxIpP37z3wCrpXn2hJhIrXdKGT1Wb
h+jnSihtUvWb0d5o39ZF0OAMYMCAAxiRmAN07rWUpTK/1nuaCerEuGY6B5EOaPOU
ZftwQNJd8Tky66xDR6Uw7LphyFT5uIDTwMNmAIBYfEVWba3ia9WjlL4JO0wPJLWv
/vjsbFs+V/uJAlqbwWdpkyEx4W08lO/KsY0N8GEgPMU+YQO8ctVZS/1AymU4D0Sp
qFHcsHVJX8AzqKWAcaG9eP4FL2ZVVkjrS3GdKv6LSID42tbxWBi6F4+JJ0yHC+m5
brCMRsQAQMwu/h37Gxho3TGd48NKMqY6tusSJCCaQZaAzHkC0XKNTfnhAiEAjNfU
UPhvCtlO7kzkaah1bR69EFgkGUPq/7CzVFhekk0CggEADZ9eB2G029GDPWqxqWGg
mWxfIjA/cthMFA9nxDHZSrVxW+qBoMmNOc5Lz3jWuevIldNP6J2UCR1YSGFe8V9e
hvEdlvbJaeID3fpYNWQgpJy0RLWVuQGpM8/gdntZTxige3+R3s26RGuImQ948v+R
8v581D/S5G0Y6tofe7ZgLGF/bvOksoTy/ZuhCjYELej6h6LKNll/7IEVehSF5EBB
3wKDARHLiAu+btSUgUiG+WXNwxNfXM8Tg3KL9luAb5aSwLENbEwJx1pso7QBPLFq
ssEF9r4jrqkADqsheJhflyyYBX4chuROchhojqSuDzY23Mp0XJ3NTmr/tnzLwT1h
MQOCAQUAAoIBAH2VOXSgO0dvgFaiMq2Owyu+EAyvaSxdbDD68TqGrFSD6L1RW5Vu
fUZRja0fa1Ed6UF6xvGpUvNlRE1cIVUd6uSlRQQbd1+BdN1aNf7aDrzlmwdviVbm
RyhmqjMI2xB3YEw9NUSGfhRdZPxftf9RS+4vNIu/NTacf9nbD4bHJV0Koo2Rawd1
ALbYpNhAlO4FsW80KmDvy94312p6dn5RSBoh32YcT+Bs0gypLKze20l/NTq6gmYD
zp9rjPHbNFTSaQv8DZM07ge304HKGOopgQdEXnJ2EAWu0sgd3VrSHuPZDuMaN6A0
i+SBNHNrOn69R8h59VvdWccYsNPGZQ41ohw=
-----END PUBLIC KEY-----
`

func Test_MarshalPKCS8_Check(t *testing.T) {
    test_MarshalPKCS8_Check(t, privPKCS8PEM, pubPKCS8PEM)
}

func test_MarshalPKCS8_Check(t *testing.T, priv, pub string) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    parsedPub, err := ParsePKCS8PublicKey(decodePEM(pub))
    if err != nil {
        t.Errorf("ParsePKCS8PublicKey error: %s", err)
        return
    }

    parsedPriv, err := ParsePKCS8PrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParsePKCS8PrivateKey error: %s", err)
        return
    }

    data := "123tesfd!dfsign"
    hash := sha256.Sum256([]byte(data))

    r, s, err := dsa.Sign(rand.Reader, parsedPriv, hash[:])
    assertNoError(err, "test_MarshalPKCS8_Check-sig-Error")

    veri := dsa.Verify(parsedPub, hash[:], r, s)
    assertTrue(veri, "test_MarshalPKCS8_Check-veri")

}
