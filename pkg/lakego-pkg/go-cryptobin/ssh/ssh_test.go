package ssh

import (
    "fmt"
    "errors"
    "crypto"
    "testing"
    "encoding/pem"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func testParseSSHKey(fileData string, pass string) (string, string, error) {
    var block *pem.Block
    if block, _ = pem.Decode([]byte(fileData)); block == nil {
        return "", "", errors.New("ssh: data is not pem")
    }

    var sshKey crypto.PrivateKey
    var comment string
    var err error

    if pass != "" {
        sshKey, comment, err = ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte(pass))
    } else {
        sshKey, comment, err = ParseOpenSSHPrivateKey(block.Bytes)
    }

    if err != nil {
        return "", "", errors.New("ssh: sshKey is error. " + err.Error())
    }

    sshkeyData := fmt.Sprintf("%#v", sshKey)
    return sshkeyData, comment, nil
}

var testSSHkey = `
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`

func Test_ParseSSHKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sshkeyName, sshComment, err := testParseSSHKey(testSSHkey, "")
    assertError(err, "ParseSSHKey")
    assertNotEmpty(sshkeyName, "ParseSSHKey")
    assertNotEmpty(sshComment, "ParseSSHKey")

    assertEqual(sshComment, "23972@LAPTOP-06E8UOOO", "ParseSSHKey")
}

var testSSHkeyRSAEn = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBb
dG9y3EVBGpvbfIDNC364AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAAB
AQCbpqbMYWlbDmJ6IeR6+JRIRdfd4UR+HYMqG5LYWv+bcXZ7NwdYOlt57bGtdQaU
CuX40M71h2eBaqKRxuzS5g4TAlh1Ur0Iqd6x/JMhbGVifT7etKKr3ejuEilIoOlH
Ymp7K0ryoEuoVWCoE8IFp6vBekkQEyjXViRWnUijV/WKGq5nL62VYFzqP+n1UnFa
2f9xLK4ZVhn+sj/A1Ec9PEta7wpSlGkvICkR+nvad884aATjd5qZ8jQI/ZTMxJiY
IEfmFElBxTkofsT7MAM95C04k5LRmuqMqHTq9p3QTvU92/ptIcV5sRlmdChM6dob
YzvuEmR7Yt/0pa62TlNkPDuJAAADwK8pB6HjK32/weS4kFYvZGHAGEvUC02srP7r
txjTYWWOZYth+OCKDklzZmIToYaCtrf8Eofv6Xc2AAGcYMrTeYHy4ENSBUtIi/ab
VcHGcvo0fgp6iuYphkTXD7pgKx1HqrBZHu4WD4/aAKDO7LZGq9d2VoveMy7j6PPr
1ffgr0ctTsp2sggGMYqPfXZCMSi7wG6sRMAM+l+O8P/Stf6lmtoscPJRTeDbEinR
UcNpN9Abm+ugfxEmQ/i2ct4WtSeRn1lnJd0bl//gHBS21E6YP+lzldfEd9Sp+olO
TgMlZzz/8y5sgHjdzscm6IlCH9EDsSb6pYWvg+TdnZgvJY/5lKSKOcJs+/cGBYSw
Dkh9YQMuZAPIBRzdLYAl/VD3w23c/3/esx6NAf51OR1Zs2oFJyk5CDEKZLS5m+b8
xddNdVUQUZJvQCqZerRTsGUbRDET3XYEms8G1u6kLAubxpZXOgkPuWpXmj824/Ay
PqYIKkVrUq6dapUzPqmHSsV0q/6DRnVXWRKfIQLtgFZ82JyfFaGmfWlFetRuiIAq
6HnMMrJHVZGISprUanL8MIi8wLWG+JjhB0/f1cdlA3hqY0P6js+IqrrKlV/lPIXL
aWHAwyB8pF5LPwFLT8rfn+fzyFxtpjrrenSUO/OVg3VFtIyYCcf6Pfc84tvNScg0
ddUIwSZUo8JlsSA8Bpc8435cnRmA/T+YZbf/qT45YYRS1879qKgS/skmRgJAA0Yt
oGLT7hmkFFw5kbN0s6yQyCPwoh8VOUKdD0Jr7OfZOo/REJtjMpE8HRZ//Ecickui
rY4xvhPC+o744c+FUlH0nqpRohG4RW1KuTvxfvgqv1jD3+LqcwksxLjgRfYO5uFQ
JbH6xhvH4u46wYsvA4CnT7AksFW/CAj1FEQ4PYf4pFeFphbeq75wZdqZpfB1iAMO
uV/UfDtVIHlhwMjNAPg/UKtUqsRb2pc3lPUGVZhIOMVzgAWzZHo/Xc4GrHIndOoM
jdxwV2mfYh5fO/RfxVKI7sXfSUA5A6gOLccnyhv8jfj7aJkf4nwyyEk2WAbe89J4
RgB8bKjM6L99AJCeeA9LgXfeZinHiVn5/HuzKAW/xTRWvudYTmODspsdow3pUKI0
Z89v0WiNLRsqQyhs11Awa7cG7z+7/XKJkSjSx9Xl4lERRjjmAq0i/mv0DYdvH5HL
oq1SfcmLHCiDPyKiwSf4D9XIjZ4Gjre17awe9u6h/wpQLlS8LWa4PsZ8CYYxppWs
e7vWWnvY6V5P9mDtDlrQAIfo/mULbA==
-----END OPENSSH PRIVATE KEY-----
`

func Test_ParseSSHKey_RSAEn(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sshkeyName, sshComment, err := testParseSSHKey(testSSHkey, "123")
    assertError(err, "ParseSSHKey_RSAEn")
    assertNotEmpty(sshkeyName, "ParseSSHKey_RSAEn")
    assertNotEmpty(sshComment, "ParseSSHKey_RSAEn")

    assertEqual(sshComment, "23972@LAPTOP-06E8UOOO", "ParseSSHKey_RSAEn")
}

func Test_ParseSSHKey_EcdsaEn(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    assertError(err, "ParseSSHKey_EcdsaEn-privateKey")

    block, err := MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        privateKey,
        "ssh",
        []byte("123"),
        Opts{
            Cipher:  GetCipherFromName("AES256CBC"),
            KDFOpts: BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    assertError(err, "ParseSSHKey_EcdsaEn-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "123")
    assertError(err, "ParseSSHKey_EcdsaEn")
    assertNotEmpty(sshkeyName, "ParseSSHKey_EcdsaEn")
    assertNotEmpty(sshComment, "ParseSSHKey_EcdsaEn")

    assertEqual(sshComment, "ssh", "ParseSSHKey_EcdsaEn")
}

func Test_ParseSSHKey_Ecdsa(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    assertError(err, "ParseSSHKey_Ecdsa-privateKey")

    block, err := MarshalOpenSSHPrivateKey(rand.Reader, privateKey, "test-ssh")
    assertError(err, "ParseSSHKey_Ecdsa-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "")
    assertError(err, "ParseSSHKey_Ecdsa")
    assertNotEmpty(sshkeyName, "ParseSSHKey_Ecdsa")
    assertNotEmpty(sshComment, "ParseSSHKey_EcdsaEn")

    assertEqual(sshComment, "test-ssh", "ParseSSHKey_Ecdsa")
}

func Test_ParseSSHKey_Ecdsa_With_Pass(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    assertError(err, "Test_ParseSSHKey_Ecdsa_With_Pass-privateKey")

    password := []byte("pass-data")

    block, err := MarshalOpenSSHPrivateKeyWithPassword(rand.Reader, privateKey, "test-ssh123", password)
    assertError(err, "Test_ParseSSHKey_Ecdsa_With_Pass-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), string(password))
    assertError(err, "Test_ParseSSHKey_Ecdsa_With_Pass")
    assertNotEmpty(sshkeyName, "Test_ParseSSHKey_Ecdsa_With_Pass-sshkeyName")
    assertNotEmpty(sshComment, "Test_ParseSSHKey_Ecdsa_With_Pass-commit")

    assertEqual(sshComment, "test-ssh123", "Test_ParseSSHKey_Ecdsa_With_Pass")
}

func test_ParseSSHKey_Ecdsa_With_Pass_And_Opts(t *testing.T, opts Opts) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    assertError(err, "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts-privateKey")

    password := []byte("pass-data")

    block, err := MarshalOpenSSHPrivateKeyWithPassword(rand.Reader, privateKey, "test-ssh123", password, opts)
    assertError(err, "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), string(password))
    assertError(err, "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts")
    assertNotEmpty(sshkeyName, "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts-sshkeyName")
    assertNotEmpty(sshComment, "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts-commit")

    assertEqual(sshComment, "test-ssh123", "test_ParseSSHKey_Ecdsa_With_Pass_And_Opts")
}

func Test_ParseSSHKey_Ecdsa_With_Pass_And_Opts(t *testing.T) {
    newOpts := func(cip Cipher) Opts {
        return Opts{
            Cipher:  cip,
            KDFOpts: BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        }
    }
    newOpts2 := func(cip Cipher) Opts {
        return Opts{
            Cipher:  cip,
            KDFOpts: BcryptbinOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        }
    }

    for name, cip := range cipherMap {
        t.Run(name + " BcryptOpts", func(t *testing.T) {
            test_ParseSSHKey_Ecdsa_With_Pass_And_Opts(t, newOpts(cip))
        })

        t.Run(name + " BcryptbinOpts", func(t *testing.T) {
            test_ParseSSHKey_Ecdsa_With_Pass_And_Opts(t, newOpts2(cip))
        })
    }
}

func Test_ParseSSHKey_EdDSA(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    _, privateKey, err := ed25519.GenerateKey(rand.Reader)
    assertError(err, "Test_ParseSSHKey_EdDSA-privateKey")

    block, err := MarshalOpenSSHPrivateKey(rand.Reader, privateKey, "test-ssh")
    assertError(err, "Test_ParseSSHKey_EdDSA-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "")
    assertError(err, "Test_ParseSSHKey_EdDSA")
    assertNotEmpty(sshkeyName, "Test_ParseSSHKey_EdDSA-sshkeyName")
    assertNotEmpty(sshComment, "Test_ParseSSHKey_EdDSA-sshComment")

    assertEqual(sshComment, "test-ssh", "Test_ParseSSHKey_EdDSA")
}

func Test_ParseSSHKey_RSA(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    assertError(err, "Test_ParseSSHKey_RSA-privateKey")

    block, err := MarshalOpenSSHPrivateKey(rand.Reader, privateKey, "test-ssh")
    assertError(err, "Test_ParseSSHKey_RSA-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "")
    assertError(err, "Test_ParseSSHKey_RSA")
    assertNotEmpty(sshkeyName, "Test_ParseSSHKey_RSA-sshkeyName")
    assertNotEmpty(sshComment, "Test_ParseSSHKey_RSA-sshComment")

    assertEqual(sshComment, "test-ssh", "Test_ParseSSHKey_RSA")
}

func Test_ParseSSHKey_SM2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := sm2.GenerateKey(rand.Reader)
    assertError(err, "Test_ParseSSHKey_SM2-privateKey")

    block, err := MarshalOpenSSHPrivateKey(rand.Reader, privateKey, "test-ssh")
    assertError(err, "Test_ParseSSHKey_SM2-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "")
    assertError(err, "Test_ParseSSHKey_SM2")
    assertNotEmpty(sshkeyName, "Test_ParseSSHKey_SM2-sshkeyName")
    assertNotEmpty(sshComment, "Test_ParseSSHKey_SM2-sshComment")

    assertEqual(sshComment, "test-ssh", "Test_ParseSSHKey_SM2")
}

func Test_ParseSSHKey_DSA(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey := &dsa.PrivateKey{}
    dsa.GenerateParameters(&privateKey.Parameters, rand.Reader, dsa.L2048N224)
    dsa.GenerateKey(privateKey, rand.Reader)

    block, err := MarshalOpenSSHPrivateKey(rand.Reader, privateKey, "test-ssh")
    assertError(err, "Test_ParseSSHKey_DSA-Marshal")

    blockkeyData := pem.EncodeToMemory(block)

    sshkeyName, sshComment, err := testParseSSHKey(string(blockkeyData), "")
    assertError(err, "Test_ParseSSHKey_DSA")
    assertNotEmpty(sshkeyName, "Test_ParseSSHKey_DSA-sshkeyName")
    assertNotEmpty(sshComment, "Test_ParseSSHKey_DSA-sshComment")

    assertEqual(sshComment, "test-ssh", "Test_ParseSSHKey_DSA")
}
