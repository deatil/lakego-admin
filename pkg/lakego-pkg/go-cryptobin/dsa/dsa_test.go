package dsa

import (
    "testing"
    "crypto/dsa"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func test_GenerateKey() *dsa.PrivateKey {
    priv := &dsa.PrivateKey{}
    dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160)
    dsa.GenerateKey(priv, rand.Reader)

    return priv
}

func Test_MarshalPKCS1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey()
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS1")

    //===============

    pubDer, err := MarshalPKCS1PublicKey(pub)
    assertError(err, "MarshalPKCS1-pub-Error")
    assertNotEmpty(pubDer, "MarshalPKCS1")

    parsedPub, err := ParsePKCS1PublicKey(pubDer)
    assertError(err, "MarshalPKCS1-pub-Error")
    assertEqual(pub, parsedPub, "MarshalPKCS1")

    //===============

    priDer, err := MarshalPKCS1PrivateKey(pri)
    assertError(err, "MarshalPKCS1-pri-Error")
    assertNotEmpty(priDer, "MarshalPKCS1")

    parsedPri, err := ParsePKCS1PrivateKey(priDer)
    assertError(err, "MarshalPKCS1-pri-Error")
    assertEqual(pri, parsedPri, "MarshalPKCS1")
}

func Test_MarshalPKCS8(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey()
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS8")

    //===============

    pubDer, err := MarshalPKCS8PublicKey(pub)
    assertError(err, "MarshalPKCS8PublicKey-pub-Error")
    assertNotEmpty(pubDer, "MarshalPKCS8PublicKey")

    parsedPub, err := ParsePKCS8PublicKey(pubDer)
    assertError(err, "ParsePKCS8PublicKey-pub-Error")
    assertEqual(parsedPub, pub, "MarshalPKCS8")

    //===============

    priDer, err := MarshalPKCS8PrivateKey(pri)
    assertError(err, "MarshalPKCS8PrivateKey-pri-Error")
    assertNotEmpty(priDer, "MarshalPKCS8PrivateKey")

    parsedPri, err := ParsePKCS8PrivateKey(priDer)
    assertError(err, "ParsePKCS8PrivateKey-pri-Error")
    assertEqual(parsedPri, pri, "ParsePKCS8PrivateKey")
}
