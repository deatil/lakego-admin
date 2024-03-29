package elgamal

import (
    "bytes"
    "testing"
    "math/big"
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
    var _ crypto.Decrypter = pri

    assertError(err, "GenerateKey-Error")
    assertNotEmpty(pri, "GenerateKey")
}

func Test_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertNotEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c1, c2, err := Encrypt(rand.Reader, pub, []byte(data))
    assertError(err, "Encrypt-Encrypt-Error")

    de, err := Decrypt(pri, c1, c2)
    assertError(err, "Encrypt-Decrypt-Error")

    assertEqual(string(de), data, "Encrypt-Dedata")
}

func Test_Encrypt_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertNotEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c1, c2, err := Encrypt(rand.Reader, pub, []byte(data))
    assertError(err, "Encrypt-Encrypt-Error")

    de, err := Decrypt(pri, c1, c2)
    assertError(err, "Encrypt-Decrypt-Error")

    assertEqual(string(de), data, "Encrypt-Dedata")
}

func Test_EncryptLegacy(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertNotEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c1, c2, err := EncryptLegacy(rand.Reader, pub, []byte(data))
    assertError(err, "EncryptLegacy-Encrypt-Error")

    de, err := DecryptLegacy(pri, c1, c2)
    assertError(err, "EncryptLegacy-Decrypt-Error")

    assertEqual(string(de), data, "EncryptLegacy-Dedata")
}

func Test_EncryptAsn1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "Encrypt-Error")
    assertNotEmpty(pri, "Encrypt")

    data := "123tesfd!df"

    c, err := EncryptASN1(rand.Reader, pub, []byte(data))
    assertError(err, "Encrypt-Encrypt-Error")

    de, err := DecryptASN1(pri, c)
    assertError(err, "Encrypt-Decrypt-Error")

    assertEqual(string(de), data, "Encrypt-Dedata")
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

func Test_MarshalPKCS1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalPKCS1-Error")
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

    pri, err := GenerateKey(rand.Reader, testBitsize, testProbability)
    pub := &pri.PublicKey

    assertError(err, "MarshalPKCS8-Error")
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

// This is the 1024-bit MODP group from RFC 5114, section 2.1:
const primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

const generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func fromHex(hex string) *big.Int {
    n, ok := new(big.Int).SetString(hex, 16)
    if !ok {
        panic("failed to parse hex number")
    }
    return n
}

func TestEncryptDecrypt(t *testing.T) {
    priv := &PrivateKey{
        PublicKey: PublicKey{
            G: fromHex(generatorHex),
            P: fromHex(primeHex),
        },
        X: fromHex("42"),
    }
    priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

    message := []byte("hello world")
    c1, c2, err := Encrypt(rand.Reader, &priv.PublicKey, message)
    if err != nil {
        t.Errorf("error encrypting: %s", err)
    }

    message2, err := Decrypt(priv, c1, c2)
    if err != nil {
        t.Errorf("error decrypting: %s", err)
    }

    if !bytes.Equal(message2, message) {
        t.Errorf("decryption failed, got: %x, want: %x", message2, message)
    }
}

func TestDecryptBadKey(t *testing.T) {
    priv := &PrivateKey{
        PublicKey: PublicKey{
            G: fromHex(generatorHex),
            P: fromHex("2"),
        },
        X: fromHex("42"),
    }
    priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)
    c1, c2 := fromHex("8"), fromHex("8")
    if _, err := Decrypt(priv, c1, c2); err == nil {
        t.Errorf("unexpected success decrypting")
    }
}

func Test_Decrypt_Check(t *testing.T) {
    priv := &PrivateKey{
        PublicKey: PublicKey{
            G: fromHex(generatorHex),
            P: fromHex(primeHex),
        },
        X: fromHex("42"),
    }
    priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

    message := []byte("hello world")

    c1 := fromHex("0132ff125d89d69ef4395272aa66533d34a221a9e3ccdfaf090ada47095cf061d7ae212bc7fe11edf3a94146b8c2f1667a47188343c477d2f58cc4419f3fc7b948cf1d931b9a3ee8d69b19dfe6d3c2fecf3c17f30d51e5a06b62408929546b7292219ac84ade0fd071f4132df864c30c6eaf831c2fa573ee09ce56d453978e7a")
    c2 := fromHex("253fd911e7f3e36681859db6dbef26287fede290f18fb7e875b9c19cc8e2e4b474975cf2f7c0028cd49d37e5c47b1995761207c99d78f78ca44f2c5e9af1db58db3c5ee2185233512d0dece8cfed00679064e3d27da5b0052dbb49dbbcac559fcfc39332465fd3e764c9dba7d8c5efbc5b2e690bff2865f106eaca3ce781e403")

    message2, err := Decrypt(priv, c1, c2)
    if err != nil {
        t.Errorf("error decrypting: %s", err)
    }

    if !bytes.Equal(message2, message) {
        t.Errorf("decryption failed, got: %x, want: %x", message2, message)
    }
}
