package sdsa

import (
    "testing"
    "crypto"
    "crypto/rand"
    "crypto/sha256"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func testGenerateKey() (*PrivateKey, error) {
    var pri PrivateKey
    var err error

    err = GenerateParameters(&pri.Parameters, rand.Reader, L1024N160)
    if err != nil {
        return nil, err
    }

    err = GenerateKey(&pri, rand.Reader)
    if err != nil {
        return nil, err
    }

    return &pri, nil
}

func Test_GenerateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    pri, err := testGenerateKey()

    var _ crypto.Signer = pri
    var _ crypto.SignerOpts = &SignerOpts{}

    assertNoError(err, "GenerateKey-Error")
    assertNotEmpty(pri, "GenerateKey")
}

func Test_Equal(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)

    pri1, _ := testGenerateKey()
    pub1 := &pri1.PublicKey

    pri2, _ := testGenerateKey()
    pub2 := &pri2.PublicKey

    assertTrue(pri1.Equal(pri1), "pri")
    assertTrue(pub1.Equal(pub1), "pub")

    assertTrue(!pri1.Equal(pri2), "pri 2")
    assertTrue(!pub1.Equal(pub2), "pub 2")
}

func Test_Sign(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    pri, err := testGenerateKey()
    pub := &pri.PublicKey

    assertNoError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"

    r, s, err := Sign(rand.Reader, pri, sha256.New, []byte(data))
    assertNoError(err, "Sign-sig-Error")

    veri := Verify(pub, sha256.New, []byte(data), r, s)
    assertTrue(veri, "Sign-veri")
}

func Test_SignASN1(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    pri, err := testGenerateKey()
    pub := &pri.PublicKey

    assertNoError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"

    sig, err := SignASN1(rand.Reader, pri, sha256.New, []byte(data))
    assertNoError(err, "Sign-sig-Error")

    veri, _ := VerifyASN1(pub, sha256.New, []byte(data), sig)
    assertTrue(veri, "Sign-veri")
}

func Test_SignBytes(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    pri, err := testGenerateKey()
    pub := &pri.PublicKey

    assertNoError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"

    sig, err := SignBytes(rand.Reader, pri, sha256.New, []byte(data))
    assertNoError(err, "Sign-sig-Error")

    veri := VerifyBytes(pub, sha256.New, []byte(data), sig)
    assertTrue(veri, "Sign-veri-Error")
}

func Test_SignVerify(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    pri, err := testGenerateKey()
    pub := &pri.PublicKey

    assertNoError(err, "Sign-Error")
    assertNotEmpty(pri, "Sign")

    data := "123tesfd!dfsign"

    sig, err := pri.Sign(rand.Reader, []byte(data), &SignerOpts{
        Hash: sha256.New,
    })
    assertNoError(err, "Sign-sig-Error")

    veri, _ := pub.Verify([]byte(data), sig, &SignerOpts{
        Hash: sha256.New,
    })
    assertTrue(veri, "Sign-veri")
}
