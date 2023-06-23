package elgamal

import (
    "testing"
    "crypto/rand"
    "crypto/sha256"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testBitsize = 256
var testProbability = 64

func Test_GenerateKey(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)

    assertError(err, "GenerateKey-Error")
    assertEmpty(pri, "GenerateKey")
}

func Test_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c1, c2, err := pub.Encrypt(rand.Reader, []byte(data))
    assertError(err, "Encrypt-Encrypt-Error")

    de, err := pri.Decrypt(c1, c2)
    assertError(err, "Encrypt-Decrypt-Error")

    assertEqual(string(de), data, "Encrypt-Dedata")
}

func Test_EncryptAsn1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c, err := pub.EncryptAsn1(rand.Reader, []byte(data))
    assertError(err, "Encrypt-Encrypt-Error")

    de, err := pri.DecryptAsn1(c)
    assertError(err, "Encrypt-Decrypt-Error")

    assertEqual(string(de), data, "Encrypt-Dedata")
}

func Test_Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Sign-Error")
    assertEmpty(pri, "Sign")

    data := "123tesfd!dfsign"
    hash := sha256.Sum256([]byte(data))

    sig, err := SignASN1(rand.Reader, pri, hash[:])
    assertError(err, "Sign-sig-Error")

    veri, _ := VerifyASN1(pub, hash[:], sig)
    assertBool(veri, "Sign-veri")
}

func Test_MarshalPKCS1(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalPKCS1-Error")
    assertEmpty(pri, "MarshalPKCS1")

    //===============

    pubDer, err := MarshalPKCS1PublicKey(pub)
    assertError(err, "MarshalPKCS1-pub-Error")
    assertEmpty(pubDer, "MarshalPKCS1")

    parsedPub, err := ParsePKCS1PublicKey(pubDer)
    assertError(err, "MarshalPKCS1-pub-Error")
    assertEqual(pub, parsedPub, "MarshalPKCS1")

    //===============

    priDer, err := MarshalPKCS1PrivateKey(pri)
    assertError(err, "MarshalPKCS1-pri-Error")
    assertEmpty(priDer, "MarshalPKCS1")

    parsedPri, err := ParsePKCS1PrivateKey(priDer)
    assertError(err, "MarshalPKCS1-pri-Error")
    assertEqual(pri, parsedPri, "MarshalPKCS1")
}

func Test_MarshalPKCS8(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalPKCS8-Error")
    assertEmpty(pri, "MarshalPKCS8")

    //===============

    pubDer, err := MarshalPKCS8PublicKey(pub)
    assertError(err, "MarshalPKCS8-pub-Error")
    assertEmpty(pubDer, "MarshalPKCS8")

    parsedPub, err := ParsePKCS8PublicKey(pubDer)
    assertError(err, "MarshalPKCS8-pub-Error")
    assertEqual(pub, parsedPub, "MarshalPKCS8")

    //===============

    priDer, err := MarshalPKCS8PrivateKey(pri)
    assertError(err, "MarshalPKCS8-pri-Error")
    assertEmpty(priDer, "MarshalPKCS8")

    parsedPri, err := ParsePKCS8PrivateKey(priDer)
    assertError(err, "MarshalPKCS8-pri-Error")
    assertEqual(pri, parsedPri, "MarshalPKCS8")
}

var testXMLPrivateKey = `
<EIGamalKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
    <X>BjtroR34tS5cvF5YNJaxmOjGDas43wKFunHCYS4P6CQ=</X>
</EIGamalKeyValue>
`;
var testXMLPublicKey = `
<EIGamalKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
</EIGamalKeyValue>
`;

func Test_MarshalXML(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalXML-Error")
    assertEmpty(pri, "MarshalXML")

    //===============

    pubDer, err := MarshalXMLPublicKey(pub)
    assertError(err, "MarshalXML-pub-Error")
    assertEmpty(pubDer, "MarshalXML")

    parsedPub, err := ParseXMLPublicKey(pubDer)
    assertError(err, "MarshalXML-pub-Error")
    assertEqual(pub, parsedPub, "MarshalXML")

    //===============

    priDer, err := MarshalXMLPrivateKey(pri)
    assertError(err, "MarshalXML-pri-Error")
    assertEmpty(priDer, "MarshalXML")

    parsedPri, err := ParseXMLPrivateKey(priDer)
    assertError(err, "MarshalXML-pri-Error")
    assertEqual(pri, parsedPri, "MarshalXML")

    //===============

    _, err = ParseXMLPublicKey([]byte(testXMLPublicKey))
    assertError(err, "MarshalXML-pub-Error")

    _, err = ParseXMLPrivateKey([]byte(testXMLPrivateKey))
    assertError(err, "MarshalXML-pri-Error")
}
