package egdsa

import (
    "testing"
    "crypto"
    "crypto/rand"
    "crypto/sha256"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testBitsize = 256
var testProbability = 64

func Test_GenerateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)

    var _ crypto.Signer = pri

    assertError(err, "GenerateKey-Error")
    assertNotEmpty(pri, "GenerateKey")
}

func Test_Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"
    hash := sha256.Sum256([]byte(data))

    r, s, err := Sign(rand.Reader, pri, hash[:])
    assertError(err, "Sign-sig-Error")

    veri, _ := Verify(pub, hash[:], r, s)
    assertBool(veri, "Sign-veri")
}

func Test_SignASN1(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"
    hash := sha256.Sum256([]byte(data))

    sig, err := SignASN1(rand.Reader, pri, hash[:])
    assertError(err, "Sign-sig-Error")

    veri, _ := VerifyASN1(pub, hash[:], sig)
    assertBool(veri, "Sign-veri")
}

var testXMLPrivateKey = `
<EGDSAKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
    <X>BjtroR34tS5cvF5YNJaxmOjGDas43wKFunHCYS4P6CQ=</X>
</EGDSAKeyValue>
`;
var testXMLPublicKey = `
<EGDSAKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
</EGDSAKeyValue>
`;

func Test_MarshalXML(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalXML-Error")
    assertNotEmpty(pri, "MarshalXML")

    //===============

    pubDer, err := MarshalXMLPublicKey(pub)
    assertError(err, "MarshalXML-pub-Error")
    assertNotEmpty(pubDer, "MarshalXML")

    parsedPub, err := ParseXMLPublicKey(pubDer)
    assertError(err, "MarshalXML-pub-Error")
    assertEqual(pub, parsedPub, "MarshalXML")

    //===============

    priDer, err := MarshalXMLPrivateKey(pri)
    assertError(err, "MarshalXML-pri-Error")
    assertNotEmpty(priDer, "MarshalXML")

    parsedPri, err := ParseXMLPrivateKey(priDer)
    assertError(err, "MarshalXML-pri-Error")
    assertEqual(pri, parsedPri, "MarshalXML")

    //===============

    _, err = ParseXMLPublicKey([]byte(testXMLPublicKey))
    assertError(err, "MarshalXML-pub-Error")

    _, err = ParseXMLPrivateKey([]byte(testXMLPrivateKey))
    assertError(err, "MarshalXML-pri-Error")
}
