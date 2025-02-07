package pkcs1

import (
    "bytes"
    "strings"
    "testing"
    "crypto/x509"
    "crypto/rand"
    "encoding/pem"
    "encoding/base64"
)

func TestDecrypt(t *testing.T) {
    for i, data := range testData {
        t.Logf("test %v. %v", i, data.kind)
        block, rest := pem.Decode(data.pemData)
        if len(rest) > 0 {
            t.Error("extra data")
        }
        der, err := DecryptPEMBlock(block, data.password)
        if err != nil {
            t.Error("decrypt failed: ", err)
            continue
        }
        if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
            t.Error("invalid private key: ", err)
        }
        plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
        if err != nil {
            t.Fatal("cannot decode test DER data: ", err)
        }
        if !bytes.Equal(der, plainDER) {
            t.Error("data mismatch")
        }
    }
}

func TestEncrypt(t *testing.T) {
    for i, data := range testData {
        t.Logf("test %v. %v", i, data.kind)
        plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
        if err != nil {
            t.Fatal("cannot decode test DER data: ", err)
        }
        password := []byte("kremvax1")
        block, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, data.kind)
        if err != nil {
            t.Error("encrypt: ", err)
            continue
        }

        if !IsEncryptedPEMBlock(block) {
            t.Error("PEM block does not appear to be encrypted")
        }
        if block.Type != "RSA PRIVATE KEY" {
            t.Errorf("unexpected block type; got %q want %q", block.Type, "RSA PRIVATE KEY")
        }
        if block.Headers["Proc-Type"] != "4,ENCRYPTED" {
            t.Errorf("block does not have correct Proc-Type header")
        }
        der, err := DecryptPEMBlock(block, password)
        if err != nil {
            t.Error("decrypt: ", err)
            continue
        }
        if !bytes.Equal(der, plainDER) {
            t.Errorf("data mismatch")
        }
    }
}

var testData = []struct {
    kind     Cipher
    password []byte
    pemData  []byte
    plainDER string
}{
    {
        kind:     CipherDESCBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,34F09A4FC8DE22B5

WXxy8kbZdiZvANtKvhmPBLV7eVFj2A5z6oAxvI9KGyhG0ZK0skfnt00C24vfU7m5
ICXeoqP67lzJ18xCzQfHjDaBNs53DSDT+Iz4e8QUep1xQ30+8QKX2NA2coee3nwc
6oM1cuvhNUDemBH2i3dKgMVkfaga0zQiiOq6HJyGSncCMSruQ7F9iWEfRbFcxFCx
qtHb1kirfGKEtgWTF+ynyco6+2gMXNu70L7nJcnxnV/RLFkHt7AUU1yrclxz7eZz
XOH9VfTjb52q/I8Suozq9coVQwg4tXfIoYUdT//O+mB7zJb9HI9Ps77b9TxDE6Gm
4C9brwZ3zg2vqXcwwV6QRZMtyll9rOpxkbw6NPlpfBqkc3xS51bbxivbO/Nve4KD
r12ymjFNF4stXCfJnNqKoZ50BHmEEUDu5Wb0fpVn82XrGw7CYc4iug==
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBPAIBAAJBAPASZe+tCPU6p80AjHhDkVsLYa51D35e/YGa8QcZyooeZM8EHozo
KD0fNiKI+53bHdy07N+81VQ8/ejPcRoXPlsCAwEAAQJBAMTxIuSq27VpR+zZ7WJf
c6fvv1OBvpMZ0/d1pxL/KnOAgq2rD5hDtk9b0LGhTPgQAmrrMTKuSeGoIuYE+gKQ
QvkCIQD+GC1m+/do+QRurr0uo46Kx1LzLeSCrjBk34wiOp2+dwIhAPHfTLRXS2fv
7rljm0bYa4+eDZpz+E8RcXEgzhhvcQQ9AiAI5eHZJGOyml3MXnQjiPi55WcDOw0w
glcRgT6QCEtz2wIhANSyqaFtosIkHKqrDUGfz/bb5tqMYTAnBruVPaf/WEOBAiEA
9xORWeRG1tRpso4+dYy4KdDkuLPIO01KY6neYGm3BCM=`,
    },
    {
        kind:     CipherDESEDE3CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,C1F4A6A03682C2C7

0JqVdBEH6iqM7drTkj+e2W/bE3LqakaiWhb9WUVonFkhyu8ca/QzebY3b5gCvAZQ
YwBvDcT/GHospKqPx+cxDHJNsUASDZws6bz8ZXWJGwZGExKzr0+Qx5fgXn44Ms3x
8g1ENFuTXtxo+KoNK0zuAMAqp66Llcds3Fjl4XR18QaD0CrVNAfOdgATWZm5GJxk
Fgx5f84nT+/ovvreG+xeOzWgvtKo0UUZVrhGOgfKLpa57adumcJ6SkUuBtEFpZFB
ldw5w7WC7d13x2LsRkwo8ZrDKgIV+Y9GNvhuCCkTzNP0V3gNeJpd201HZHR+9n3w
3z0VjR/MGqsfcy1ziEWMNOO53At3zlG6zP05aHMnMcZoVXadEK6L1gz++inSSDCq
gI0UJP4e3JVB7AkgYymYAwiYALAkoEIuanxoc50njJk=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOwIBAAJBANOCXKdoNS/iP/MAbl9cf1/SF3P+Ns7ZeNL27CfmDh0O6Zduaax5
NBiumd2PmjkaCu7lQ5JOibHfWn+xJsc3kw0CAwEAAQJANX/W8d1Q/sCqzkuAn4xl
B5a7qfJWaLHndu1QRLNTRJPn0Ee7OKJ4H0QKOhQM6vpjRrz+P2u9thn6wUxoPsef
QQIhAP/jCkfejFcy4v15beqKzwz08/tslVjF+Yq41eJGejmxAiEA05pMoqfkyjcx
fyvGhpoOyoCp71vSGUfR2I9CR65oKh0CIC1Msjs66LlfJtQctRq6bCEtFCxEcsP+
eEjYo/Sk6WphAiEAxpgWPMJeU/shFT28gS+tmhjPZLpEoT1qkVlC14u0b3ECIQDX
tZZZxCtPAm7shftEib0VU77Lk8MsXJcx2C4voRsjEw==`,
    },
    {
        kind:     CipherAES128CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D4492E793FC835CC038A728ED174F78A

EyfQSzXSjv6BaNH+NHdXRlkHdimpF9izWlugVJAPApgXrq5YldPe2aGIOFXyJ+QE
ZIG20DYqaPzJRjTEbPNZ6Es0S2JJ5yCpKxwJuDkgJZKtF39Q2i36JeGbSZQIuWJE
GZbBpf1jDH/pr0iGonuAdl2PCCZUiy+8eLsD2tyviHUkFLOB+ykYoJ5t8ngZ/B6D
33U43LLb7+9zD4y3Q9OVHqBFGyHcxCY9+9Qh4ZnFp7DTf6RY5TNEvE3s4g6aDpBs
3NbvRVvYTgs8K9EPk4K+5R+P2kD8J8KvEIGxVa1vz8QoCJ/jr7Ka2rvNgPCex5/E
080LzLHPCrXKdlr/f50yhNWq08ZxMWQFkui+FDHPDUaEELKAXV8/5PDxw80Rtybo
AVYoCVIbZXZCuCO81op8UcOgEpTtyU5Lgh3Mw5scQL0=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOgIBAAJBAMBlj5FxYtqbcy8wY89d/S7n0+r5MzD9F63BA/Lpl78vQKtdJ5dT
cDGh/rBt1ufRrNp0WihcmZi7Mpl/3jHjiWECAwEAAQJABNOHYnKhtDIqFYj1OAJ3
k3GlU0OlERmIOoeY/cL2V4lgwllPBEs7r134AY4wMmZSBUj8UR/O4SNO668ElKPE
cQIhAOuqY7/115x5KCdGDMWi+jNaMxIvI4ETGwV40ykGzqlzAiEA0P9oEC3m9tHB
kbpjSTxaNkrXxDgdEOZz8X0uOUUwHNsCIAwzcSCiGLyYJTULUmP1ESERfW1mlV78
XzzESaJpIM/zAiBQkSTcl9VhcJreQqvjn5BnPZLP4ZHS4gPwJAGdsj5J4QIhAOVR
B3WlRNTXR2WsJ5JdByezg9xzdXzULqmga0OE339a`,
    },
    {
        kind:     CipherAES192CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,E2C9FB02BCA23ADE1829F8D8BC5F5369

cqVslvHqDDM6qwU6YjezCRifXmKsrgEev7ng6Qs7UmDJOpHDgJQZI9fwMFUhIyn5
FbCu1SHkLMW52Ld3CuEqMnzWMlhPrW8tFvUOrMWPYSisv7nNq88HobZEJcUNL2MM
Y15XmHW6IJwPqhKyLHpWXyOCVEh4ODND2nV15PCoi18oTa475baxSk7+1qH7GuIs
Rb7tshNTMqHbCpyo9Rn3UxeFIf9efdl8YLiMoIqc7J8E5e9VlbeQSdLMQOgDAQJG
ReUtTw8exmKsY4gsSjhkg5uiw7/ZB1Ihto0qnfQJgjGc680qGkT1d6JfvOfeYAk6
xn5RqS/h8rYAYm64KnepfC9vIujo4NqpaREDmaLdX5MJPQ+SlytITQvgUsUq3q/t
Ss85xjQEZH3hzwjQqdJvmA4hYP6SUjxYpBM+02xZ1Xw=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOwIBAAJBAMGcRrZiNNmtF20zyS6MQ7pdGx17aFDl+lTl+qnLuJRUCMUG05xs
OmxmL/O1Qlf+bnqR8Bgg65SfKg21SYuLhiMCAwEAAQJBAL94uuHyO4wux2VC+qpj
IzPykjdU7XRcDHbbvksf4xokSeUFjjD3PB0Qa83M94y89ZfdILIqS9x5EgSB4/lX
qNkCIQD6cCIqLfzq/lYbZbQgAAjpBXeQVYsbvVtJrPrXJAlVVQIhAMXpDKMeFPMn
J0g2rbx1gngx0qOa5r5iMU5w/noN4W2XAiBjf+WzCG5yFvazD+dOx3TC0A8+4x3P
uZ3pWbaXf5PNuQIgAcdXarvhelH2w2piY1g3BPeFqhzBSCK/yLGxR82KIh8CIQDD
+qGKsd09NhQ/G27y/DARzOYtml1NvdmCQAgsDIIOLA==`,
    },
    {
        kind:     CipherAES256CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8E7ED5CD731902CE938957A886A5FFBD

4Mxr+KIzRVwoOP0wwq6caSkvW0iS+GE2h2Ov/u+n9ZTMwL83PRnmjfjzBgfRZLVf
JFPXxUK26kMNpIdssNnqGOds+DhB+oSrsNKoxgxSl5OBoYv9eJTVYm7qOyAFIsjr
DRKAcjYCmzfesr7PVTowwy0RtHmYwyXMGDlAzzZrEvaiySFFmMyKKvtoavwaFoc7
Pz3RZScwIuubzTGJ1x8EzdffYOsdCa9Mtgpp3L136+23dOd6L/qK2EG2fzrJSHs/
2XugkleBFSMKzEp9mxXKRfa++uidQvMZTFLDK9w5YjrRvMBo/l2BoZIsq0jAIE1N
sv5Z/KwlX+3MDEpPQpUwGPlGGdLnjI3UZ+cjgqBcoMiNc6HfgbBgYJSU6aDSHuCk
clCwByxWkBNgJ2GrkwNrF26v+bGJJJNR4SKouY1jQf0=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOgIBAAJBAKy3GFkstoCHIEeUU/qO8207m8WSrjksR+p9B4tf1w5k+2O1V/GY
AQ5WFCApItcOkQe/I0yZZJk/PmCqMzSxrc8CAwEAAQJAOCAz0F7AW9oNelVQSP8F
Sfzx7O1yom+qWyAQQJF/gFR11gpf9xpVnnyu1WxIRnDUh1LZwUsjwlDYb7MB74id
oQIhANPcOiLwOPT4sIUpRM5HG6BF1BI7L77VpyGVk8xNP7X/AiEA0LMHZtk4I+lJ
nClgYp4Yh2JZ1Znbu7IoQMCEJCjwKDECIGd8Dzm5tViTkUW6Hs3Tlf73nNs65duF
aRnSglss8I3pAiEAonEnKruawgD8RavDFR+fUgmQiPz4FnGGeVgfwpGG1JECIBYq
PXHYtPqxQIbD2pScR5qum7iGUh11lEUPkmt+2uqS`,
    },
    {
        // generated with:
        // openssl genrsa -aes128 -passout pass:asdf -out server.orig.key 128
        kind:     CipherAES128CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6ei/MlytjE0FFgZOGQ+jrwomKfpl8kdefeE0NSt/DMRrw8OacHAzBNi3pPEa0eX3
eND9l7C9meCirWovjj9QWVHrXyugFuDIqgdhQ8iHTgCfF3lrmcttVrbIfMDw+smD
hTP8O1mS/MHl92NE0nhv0w==
-----END RSA TESTING KEY-----`)),
        plainDER: `
MGMCAQACEQC6ssxmYuauuHGOCDAI54RdAgMBAAECEQCWIn6Yv2O+kBcDF7STctKB
AgkA8SEfu/2i3g0CCQDGNlXbBHX7kQIIK3Ww5o0cYbECCQDCimPb0dYGsQIIeQ7A
jryIst8=`,
    },
}

var incompleteBlockPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6L8yXK2MTQUWBk4ZD6OvCiYp+mXyR1594TQ1K38MxGvDw5pwcDME2Lek8RrR5fd40P2XsL2Z4KKt
ai+OP1BZUetfK6AW4MiqB2FDyIdOAJ8XeWuZy21Wtsh8wPD6yYOFM/w7WZL8weX3Y0TSeG/T
-----END RSA TESTING KEY-----`)

func TestIncompleteBlock(t *testing.T) {
    // incompleteBlockPEM contains ciphertext that is not a multiple of the
    // block size. This previously panicked. See #11215.
    block, _ := pem.Decode([]byte(incompleteBlockPEM))
    _, err := DecryptPEMBlock(block, []byte("foo"))
    if err == nil {
        t.Fatal("Bad PEM data decrypted successfully")
    }
    const expectedSubstr = "block size"
    if e := err.Error(); !strings.Contains(e, expectedSubstr) {
        t.Fatalf("Expected error containing %q but got: %q", expectedSubstr, e)
    }
}

func testingKey(s string) string {
    return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY")
}

func testKeyEncryptPEMBlock(t *testing.T, key string) {
    block, _ := pem.Decode([]byte(key))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", bys, []byte("123"), CipherDESCTR)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if !IsEncryptedPEMBlock(enblock) {
        t.Error("PEM enblock does not appear to be encrypted")
    }
    if enblock.Type != "RSA PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }
    if enblock.Headers["Proc-Type"] != "4,ENCRYPTED" {
        t.Errorf("enblock does not have correct Proc-Type header")
    }
}

var testKey_DES_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CTR,FF234E7A492EF147

95VoY+f+oWf5OTIcyBiemd1Jy3v7LLRkPuBR3XhCbxxxCSNoZFoTG2fBeEUWvjfG
QZoZPfNwpUcuEb4NxRd5Mx4F3yb/54sBBB+LASdPM3Qp5eZ5sCUL1GKAO7RYHHAQ
hffU2n0Y23yr4kTlyj64MZvFUjsZRJ81wDZ0XnPc+ZXj983RZKU0JfBE4aKEP85S
etFLV1RcyQ/rpeMXDI9h+UW9B7cBVXv06PrpIMDgKJL+JGO29iBtKU6fbBsZi5IA
NIEqVJqgCW4K4KX/H2UNXREgsiJ/BGjauK6XtTUHcCfQfsxpo6FnmcB3yD/Dp3Co
knkXGbSYVEuukyK6f/BH4IPGtgRiqCrpRBziVtJx9DT1T0qgIRGLujSlr9cvMufl
I+n1tUlTxstjVxptxup+4Cfx1hWSBRIWFO2KX8q7zRhLZ5uVVugFYQ/0XL3Kz5Uv
gKE1NStuk/kc9C1T0c/P+WbBYI1Lx9LH76eJXruj2y7az189DjCsDbR+gIMirzcX
ZE67FRO79lZFy0NckHwhtbZ+4TR1bBEuLGmEfsXI0jhdnatpXC0pIAlJt3oLbjHS
qLKdU8fcyKbP1nbCMmUjALXJMIEkvc0WKkHY9gu0CcyNfTkTGgsyptG+B1TTU6il
EltrJrbDG1XEmnG8m64wFDXGNfohCgj1hRPG0uvMdMDzyYCONkFva5jTqLIj96AM
54CyCh+l8/GJytSen2BBV0yklHF5xVQpJE3XlJobSWFd8V5A1l3GbTpsJ/9p2HXC
11XWP9ztWYZ7kooXn2PXqkXxNuGPu/jj/NEjOkkV7A4=
-----END RSA PRIVATE KEY-----
`
var testKey_DES_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-OFB,B7A34B2630AC0335

V1R2CVqxohGuAwdx2ajaqCcih1skaCmw3WXqqKN3O46Of31SCCuELF+2GJ1bZmE+
aTk7l5kwCIPiGuELArIAV9iVJjJV3hhZ3lI29XtffxdQ0rtJmxWM53ta0UzYGyIz
jMcdmtBDh/emG5sqjandTih9yISaDhDycSB/UvQmgj5aBTKjJFYIJrRFfBox/5NF
zUSkkMJoEiB4kvYS8l51HJsii9c5aPEIzSbU5bmeopY0jRMNa74ruSsEBvg3/pLr
uJsBaALrdo/MeBU6LPGfInoCS7ySB2dPRlo0ONr3xDRPrXZJ0/GFCyo52vx6/PTf
gxeln5z+UYTKStt0Ub7TiyJwMSj4rTSkldeFU8f3H2ypNZoB1grzd0rgtINcMymQ
dc90Q9ATSGV2DnRzUzKkhn55oXzGXcIVqWweg4bkbtzxo+jmOchXATnrd/gWxWz3
vsDzl/67eQpCSTal/MKyQcGBD9DqzGiQYDdtKwoCDeJLhZ7Qhc0OPaqfZ8s8N/DX
bV1s6b1U906+kBHFVaPoVBug+mqzrZbd+VQg3AwemDCL5LxEf6oN6t8aFU2fNTzU
VHsyX/eZqlg7S4ftAkoHEdLGlSK0TcuARcpKmclw9wXxZdjHOSIt49nbI/OZ1xfS
Zm5dQsnkLbPK2bKALSKQfxT/RdY9V9DYKtd/OcwRssvXY+CzKPLtNbkDmicn2ucD
4fAS8FiOOzxzUwlvtuk15rznVb7D3gUm2s1k1yRk3TY78zVlMB0sjZrzsMgkvM4b
nBoLwopS2CKwWv1ttXjXY0EjRz16oR57qAjr9WIQ6v4=
-----END RSA PRIVATE KEY-----
`
var testKey_DES_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CFB,CD26768816AB735D

Nsc+eYba+4fWQuSC7vXOxw6tN4w7z9ODF9MRtO4E+0S0pV3NXHY/l/xvW9ljrGuc
3hmUKOtZ/EQbAhSZo7KyTJFbc8qbOyloag0dumwblC2qdXJYTOZat3LtaqvJ/4fJ
DVeHgYJZd17NOjh7KLS+Vr9alaua/3rAN6z7Trdc3EXcokN+h1iucg8WpzNmh7gp
ql1d8fW9EXJ0QZlH/QWQcNw6GltZ4VSbshdsUQli3f7Lsx18maMDLPnaFsUfrd3I
ePAjxTrmgsIjNafLXuYNpoESEHnPm6oPGOJBjl9e4SJqNE+yDecvIZUkkH7QiCZl
Nn/oe6RsY3mjcLpRvRhaaxQgsc0uNeSFeeLg1WsXgNDBmjWHydglsuo0PsUUxMTm
qx8fZU0yCJ5RcrrLFZcSjxZfs8RixQdElZA7VvtoomsC3K2pQJJF9ASWYVKTQQY5
nQfgGAxdwPe9z/59TMKghaW7Sq7/NEtvA4SxGxoAW/qGcbRsI0UuqIX41SQoJeiL
9yPW28r9xrNH7UXLz9cqYXsarHTVpOiKh8JnnVHzRidojC+Qoa31qBChlZl+kmuR
6XALOGm2abiaY6LzeWlb92ewS679w0fUSbi872WDafrhBdULqxguBmrlVf7zUjQL
hawM4n2mXnqGLYH0BwqiCCjiWVJyb674T2ggoJCsi5MT0M2DhldLQlRwfvoDB+Kg
A4A/aHB+V5eDqTG/UnO3UIvpx8vr7Oox2If3wc3b2mTiEAWY0AYOOiSagTOW9HLu
HV9LrrqQxBwWHEZkFurDUvA8Yw5n+D6xsag8y1JNOVOVfw==
-----END RSA PRIVATE KEY-----
`
var testKey_DES_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,56255234AC88C13D

/xfaIkSZ1Fyrh7clFM8WR0syQRm1abNsfbhZe7m310als9VhOzxfLZVflXz1Rops
AUUSZJ9th6RnT0r8visW8py95gJED91AbQWa+hDBkZZNgMpSwsLZDkeiDGwnGT+x
65mD5VtoLPDVvJ+q2aulSuwzzEsK0w5J/CnqPMy8sxaQJaWbskfGLk6xsOapXQxn
UTMhn1oMSdzFGtP/3Mf/DTCdkqqSees+UyFeBQ0n5gQZP4YttzAKODTZCq+iwCTo
S2cT6bSvhdAKJjGl2raQIx8+xWU5Y9abpJBF/ehbLqj3beUaEIsHcCLFNIbCoe+8
AFow/NyZy2hiRAyqskTu4mLIuWJkAespEwS4cZ7BTOGc7lIy0ubneeCZwaeJBWmj
EGiRlQqxCM1dwr2L/5qDvPfoCDO9fADKMyVyD+UWJpOzhXK+i64H4A8Fe7LQVecZ
OvE3L/mgYMz7KBnDRCnTLsRhg8BoJ5VbZRkQYeJrSVIVIEs9fY2PzfCb6tkSaD08
5si3m261YVAWUzQTieTYJXJCfUG2Fojwxwv+uWFqqEmjkK80zMrb1er3Em3JH/UN
u9ldvhKCxjQurl6oZEX/rVHMIPaW+ApXWWztLXlxucjDr146uXO+uGgLqKpbU+xT
1bqqLlh1a92/S3D+D/OGLw4MUaLEvl/e1q1rsGYBCl+Rvdwho9dnOES8IkHh3knz
lXgBUV+g+ijg9RjuXtYxmWqr17I34UkU1H/UjFEeuRO4WPuOFxUWpcj/wOCbHwrO
q3/+myMrI9ODCgqWMbxi2/IRUEgOK1mCbWpR/UH+WZC0e8E2PZ6L0w==
-----END RSA PRIVATE KEY-----
`

var testKey_DESEDE3_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CFB,D2C6635FFF7A4DE8

zhWXrCEVN+5fptlVImtQ/LPu0qI1ox7h7ZL//vRyp0wLnTSBbP8y5Oo8fzTmvDvm
y32CMUuCL0P5qzb+Ku3Sf8ibHicoDTZ1RtogSLVY1RImkVtI2hy6eiiyOLfryjaA
mQ4eSQ6FDkoCxXgFj1LzmNvECtTXbNzfkbdQ2TjE4AiNYTd9MSzcAHO1ASANFDlS
KYbA7QS4DIVJGdpngWUOhr0DoHq3IhNkU4it8j6qGr6l8fLw/wo+tgOAJqTd+aaL
zvZWL85h/ZgVxIZlC1E4eW+YiN/YZxPQ6pbPe3KeGzY7GNmdr7QBST9FFLZD9meE
7FZhq6b6Lef/zvEDWkJgegyUefgPdNg65IeMjMuToQsI8B0CofwkvLI63wqJFKvV
n9ukVNYzy4GJrlWNamtKpC+krz6kjW9aPZAAeMrHQzzvGbhDHs8xghd5xsGZ3nup
DtD0vlqcV/FlJvmJkeDw4BF/i3ybUdG0PsyGdEoxXsl7UpSzlG8bBSOidGtEb86o
JFtBOJnv8sALLpo0dIsu4n498Itd1ngsTEWIh+7BxQYL7yS+e+nFD8CMr1XZI2yY
HxmJ7NPk39ZEr8IIzmOwWyrR7MgC5svycx/49vFekazyO75ctxPqI4ZLkHeH2yvp
nMOlEKQaSiXRxcE9Zz197W1xFJZOF7oSvF+Ih3F4auvJcJzLk8RfvYgmAV9FJT8n
o15yE9naANp/ml1ZmFybky8cGpTYA7WTiu16PuApj9sMpfZLJjITBvvkAqccYiBt
mcOQ5xdAyTvovTQR4mxbe/SwsBtseICI7OnS4nHRcdEWcg==
-----END RSA PRIVATE KEY-----
`
var testKey_DESEDE3_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-OFB,A0D9A77A7948C56E

s+3F7lzcV6Qzp1DIrunvfmioizqAo/xp7c26amLJ3A1tZd3CUqdB2VEy+MMpsulQ
0FyyBRG4z7kjONSp7rmrjtmc4xOulWj/LLovhjQKF4TfhW1QosYReuEwVnlEneTC
zEtoq1hYWHy6KC61DK4apG5kZivuYk7R7iX7yAzBieme0PoXGHoLw3mIMEb6XQcM
MOrgimZEFsqJpOuLu4+E0asfJkW3faDwgp6llW1/ec+/qJCdsXqePLjJtR7hxjJq
TZrAwqMfkGY76547ZWLbR0yuBMTc2e8jVrM7OOm3iUOcafz2WXC8JVCwYpuys8x3
CJXlA9bytm0hGMqRE2HfmAkircHqAMMfiw4l9x1RGjU6jAxq6v5atgwFWt5/LFen
nZCebQxF2bM13nHRJmft3kYtjjH/ufA3rUl80tTvXlN+fy+9G8/ylFoNDUDn2syj
FUia2VdNQ7ddH5uWx4CDOnKwcgmsX8vUoi2j0mBOwERELMg+P5YhmuyyWlC0eK4T
8sG++teRpFpE+jOpXVNnGw26l/rEgXDfe43XGnQH/9a/L6NLeT+RJWnsEpkwHph3
g344ArmKA98JDqBCdUk3ROQPsAlbY5OAAXe8r0YImmxXnqEbkWqyRNEoBt6Sh5bJ
WQhCMsnmZoHmDgPqhrfi+H672MEQdN8SngItDCv1NGp60jvpW3VbqW25GKVy4VKc
awEw/CQpPQ7E2rF0YmWVOXZkWcnRXcY6TBcTjKvZqsjcvJAIOFw0NQy6V69Mgu53
nMXfIRLAvuBgtv2zcwdbgsvhAHOeV1d7l1EuISNRkBRx
-----END RSA PRIVATE KEY-----
`
var testKey_DESEDE3_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CTR,140F4C905495A783

tfS0emYpmj4oggZbRntqambp6eUCpppo9W4xdoOOi3Ch4Jgb8P+9SD+Qq661qocU
hQkLYWIpgto/E7iBqg/aobsY5GTYNH4dU4mcRxicv2F/joShXMkmBjfQHNy+mDWJ
nEEXAh7FjcYvxaZfvepmlwhWvsTgSo/IzBr3sCzrPr4icUJDBPx8w5/xlAFGDJAU
o4yH0kUa8MeJ1/RWOxN5nDVEt3jvnOsk8NDkQt3LPLgU3OR7S4nR2JLeaz0BGaUk
EsXo2muk2937GGWm9YfuqDeuic2QG9R3qLuCR0jYZ0rXCpU09McFzZa0geXiquZp
3VbCJucODP9x5dhqLKL4KHx8XqVRSgadhrSnxQTHPa124O6jEEtuA0eUGONYV5Uh
pEGng8f1LjJmlVq1qEDPUsjrgp0WkvV1CgwbHeWspQA+eUteYTqpYj7DHDjwcxC+
zyqkl6hMRFYTrT3RnaEgg2DWo/Mk6HhMMJyo6a+5wYsCyb5rk+iwfjSFj6jun7E5
rE5sJ5XVDA2PSN9yy7miUcty2R263+WvBf2EC6I+WrIta8m8xVS4BIjYVMoqi9fl
iX2Uhqbhx24YhNdUt8qFs3XyVqpk0fbtDlKc8yYkSwme8SquGZzoei2pf76I6GJB
DcWQkAVeV0rN8U1U9H1sGC/EBaxCDQYrvcqacQv0iU7Xe6Uf/9qkmWBc6maq9AFP
mSHYIoYDhxtZTPdfVo7JywEtujkgeFPG/6vpomarWRy8dAcUnLUct3BZb8lD55et
OmYAMAJyodew+6ZbTG3LRiyIH66NYGCU2Yhspd4ZeCc=
-----END RSA PRIVATE KEY-----
`
var testKey_DESEDE3_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9AD0BC30D5D31806

0abVBdh3wnueNE8ZiXnRzqdwAD22HoUJDwMo/j5Z/p/qc2jtZo7xjukHLkW9XoqG
WsyVeISoFVkQxaVqqN/GWWRvv3ia5Vqlfkk/z/d6ABy4e0KNudiCLijBEJRIzz2c
2qEooF0sGLAfqYPGzFsQhswltyFn3BIIVaVDEvtU0m8DA5tGjMTXZXWokH4iKYaR
31aJguKc1GxXlaxW7q4w5P2dsCvNEzXAoahte3NU9GTvR3/CUGS1QPtghT85bYdp
BUUMjidTIbBoxluAck0kG7zPdV44ql1OgLNxzhIr8eDnsjkNgkPFZDrypTGNCnQY
qZU1fxIDPicYbaMtac65LIQ9GSE2nHlZC3WR67TErf52klSjiA3qCdb5Y/LgZgTY
c/jCgTg2tBKXfN11HsriEifcFoWn6kpxGkSLDxAGXiJH4QfAYPtzsu8lJOX996S/
x/nAqFmg2BApx5tk24+zU8kCoHEjipyGcXfGoE0R+lCI/WR8HxtHzkwwVinI6ESE
EkXmK/8Q3rjEjVP9Wc/v5ELe7ViyaoqcR8+PseZ8hDm1WKcrr2ZQulJlfU32QJtc
h1GDZI0/InYvrgYRyRcrFNN2D42GCCS2/JMe/9hoSGK32TgNP5qABw52YRqC4rfJ
g6gRNObO5IqT0ouK2CfG2lInzzwtqk+MNfk6KZgH0Zu/BU/ZzEWenqXit4fn6CjV
MzdeRbCJHodEmoszEZL9JHD7jzn/k6bCBHjlnc2VXZ4TOLeT8oOZPy62uE+QDUWT
APUPXXGEi9XLRMywrz9edTGZC1nozLijCP8YT8K3t/w=
-----END RSA PRIVATE KEY-----
`

var testKey_AES_256_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CTR,04CDB0482386CB0D79252DD7F8631C83

yD4lgEiGu5U8vagEgFmP/9vdymil46KCljonxyKSjTwbeipByzZYr4WodE3iH6p1
Z5Wa3DHxEfmkRd9JfwQyOyo42HNYq+GELBL22o9vktswADulcR9KymW1TbdwRZot
gfU9DBT9dNPB2FjVS7sSkR8JBbHqLb7++UNs5eTmI+NGrARsSAdIEjkFs2uUvinB
CfztjQAGJM+3SSJg70lFOu8XtiqiRJo4U9Yjm5y8Cb+fgFjeigT2FMHLVY/ZyD34
AJHxuk2TIgAjGLoIVYCe1FeGs1+TvKlq05IKpBh+vi2fFs4nI92jfuCcQEMH+oOV
ISbbjkoRhcA+g93ISM3jsg2g4OYQv3l/xKguIbo+gdboR8ehrBCoak+cM5hEsLEG
7hNtP3HF5VVc1tnciL8k9Rhw4JA0g7+cRALP/J8fMreh3Pe/h/HH1S4ipZGaSdCY
bxyKZRkzT8o3wXYHANJjWq4abyUFm3XffgSq0XVuOQIk0BvSVW/syLSdH6Ry/kWf
mFHX5VXAjnc0nhAE+ETcV6DSEm6k4SNIe+04OXfuUlSFuUGaZHMlK4Y6+a+OR+iR
EyLBUs7WE/FgdL06fXNR/oHl+OSqkqWfzsyWVUVq5vkeIuoeF54MzX5jd4HFCynu
hPCSMfnEdlhz5fmmmynOQGgDpCkyGJlhOJGJiDbjWa5g6JKdsfWEX2e7jh3Uo3TY
2nLmYjljf6CaQtHTKmD8bFQ6QPBGwboP1AV2tLis8P5x0QAl/2iZ78r7FhE/a492
ejV6+uGxoV4nH4VtDlQD5q0UszLStTrznZGgbI+h898=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_256_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-OFB,06C6F3444FEEE2DC423F83FC8A45DEC7

PCqMsrWxghULrV3ctM4YOBrjUVPi0gcYWtXyXrHX47GugYKg8THjbAIJmeC/ntiR
1rEK7LpdW/3qMEX0CEwloppCdlRY72grBIhgzzPiyNBBSzlzrhVTe8/NN+B4zV7C
tD/Kgis/5j2NCyAKUnr0v5N5vEPeEaMDVigK+cOraev1jpd9+AMXPsn/HyiPCpW/
PF30F0RgaLz3RHNZEulkBXHApbW5elJbuXxzCOzw3PFmXRFVHixQR7/WR0iuWOUG
8t1vuXj9FZhl5HsJSI+cjNI5sMpympzb64iBZaqP5SqGkzKBkaunSWsoFZScNdyJ
51G6yuoA6bIijvQpfklgkfnEqfb6U5REnXXWokCQ3OSEpuTYkxkbZyFVF9Dp6bod
0GuirdfI8jMu8Zgm8iW6nAej5C7NvFugTg/bgxRBnUB9PdWNSLqJepBqpLvbGVcd
gIWx9dYeM0uC5oiElxiODcDxmIa/nokwLO4qoJBGgagyIwqCIqCzemuc4wcJlJ+j
L6PYrSvzh7fuSc57epzvaIIOQ+Z7PaIw4XEZi1KlEPm1ae32b/GqgkdUCmu1pKvX
3zO7U8XPiwDi75ryk7bwsZSHmggiBgFaqa4XmLC+cT/0/N0XwSdmoAfv+ls50yWi
aIMjPi9lMN79O+QuE4KjG8PfceTkONwV9REAIZh29WRlEFp4phYZbi8VI26lqebG
hvfD3e2TKrOWj04cG7IufCFqonZ+mOFvQnwzXtswLZI4nWifIwM0clkgiV8jZnWA
BXtOrl6JbjuAtbgYloRi472YWrNn4JyQx4XrfOHndNE=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_256_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CFB,FEE6BA57503D765BC6D87BC6954A0D72

bq7Nbbr5BF8Me+OXceRQQAc/S3wcD6Q9XLQgHZpwulLkw780ooTU5C51d/4JmPcM
NZDo35EPjCG4jb2wEvdWItpn7nF3LMnTOvJfcpH03NbgNfbLgn+jvckkU1ehOPoi
UHgww/4jjEGeKRTefzbjxEg4rD2aRuxe34yR8GlCOR39UxdziIQytxPvRl/Ad184
+QeqFb6cW2MgMUPkAL/PA4H1TfSg6xCET5ewMhgHTTaE9sEmDYtlxCVEkhLTr21O
avMHvLgQS+iQrE4h3iJ9jvWWsUUYTIfCpNrN0dujClX/RPETfiNhUihHXasA//qh
+0wBh3zroF/+2TEYXwPOJyHBKULEgUBxm8mdSlHLf93mkMpYs6josC3XthpPzX46
P2nC2Pt7lzs5MRNIMlj4DWCODOzuDphUJ88Gt+g5SCOl05fqRka5Qy5vSWc3v6/3
UJI9yj+eNFF7d0TjW3saMF4m7x206q90LL2d3gN4hNA2a+yVTiUQ6/HIlAebffTh
RWptkznl0BSJkvUu+jon16KnPYQvuyFiI6KN1GUKL3a58OmfNljmNYyY9dOjjT0D
IrHJbDgyuwLcQ2WhafdTDWt5Zj2U1vh2GbkNAxQzljbDku3l5wvaJvSQSHK+k2uI
0pHc3RENOFZ751b7A+H23Y7V/Kqi9tWfCqFo0Ybdc8kah1a1+zyxSrq7FEhUG8ja
EJI6g3hykcWb6Xv6g4qCNxt93nTyPIxeJsOhCiValjJGT5DxzCGjcwWKh0xCTAOF
UR9uChIsW6/OIOevnvffncQoPNOLZx8XorAdD8ABtg==
-----END RSA PRIVATE KEY-----
`
var testKey_AES_256_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,C931B17A1CEB5CAA94BF6E4213259E5A

5Pms4h8bE0a6xFznAI0Ka+38/EV7hdBK/2W+bTN0IPNAc3WIIuYrPG4yj/k8abGG
CIOcHuLGSqLW2ObAy5ZgS3Uh3mRkcuNDbt2xtk5dqRn0vArIpyIJ6Bwphu6Dudm7
E8fCKfnJHAyu0aMM950IXL+JcdnCQtHUmDd+YRdYJ8TfQVcfSi2B04pBQo872Wo9
mLS+fUuFhzh+fO+NQuc146kL9K2xBCg5CO8GL7C+RGTA+2lzYI15rTHHkgYACwso
P4RSGAaFqMxYNDSM9gHnVJrVNoRyPGtA3ke5u98iO7R9eShrsdt4BGTyt9mMzUW8
Rvx/khcHXs3wCMAH6me7EbtibB+U7u97CPGDtFopvIy5Iyu1MwH+68k8DRXwAZvA
c/t642qgfEPS9g7Jdwaj2+M+FzTkIOdeNkG1dohyskc0/NnTREax2JSizVH4a/rU
X9aly3LETUEAxXKwfc86aQ1SsdpGGIVTC+HzIt3DeJpuX2xRDDOjO0lC4WL1Jkxb
smOi5bVpHxNVG5nu5P1Su8ANjB8VAe/f0fDUkfYDeS5tG/uGkuvjkRr7MZGw6tiN
Adg7okhYQApO/oVHw+X53lP0VBfhgGaj2JOoncDJZsy5Pybqu3NsxcRGYYooCBL5
ppS85jdFQS+VfKavLIN6ruiQ7OAskrLJvHxeifZqA4Auqaf3fPIW1bStQ1TNp/X7
tD4t862ps8gvOF0agBu6ut9JoUbv9b/Jm2PaxwXOYhHIoYiL9VAb3zLz2ZQleowe
HY7vDw7uD50dvQ7V0dJM10UUYqjcgl0kE8wlwwqCSg/JuLpLDpBLx8fXie1LPRJD
-----END RSA PRIVATE KEY-----
`

var testKey_AES_192_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CTR,7239E65AC7D2250A552554E778198DB7

nB8IXLlbAiLze4VRUgUCB1qvXNwWaZSBtZAZUKkWG5qSieg0kw5oWE1dPwHe1yFh
AziHy/G7Q66+UEEA7ZA363I1+m5cniCXJbpSUD/ta9MtZ3HM+MOtbx8/r2Xcrmio
pAzs5xYqW0dlHqL8v6mZfMYxkPFE+TIr3QJniNg/kNPAA9D8Se6MPvjYa6H1KIwI
0vM4LhyZJWANC3dqg8kntZLtXatHsPR8PEm/Pa6PQgcsMiku1g4+TyoY9k03DaR0
t4e8AcI2WQb6sfzBszEqt9zyew87ArA5SY6lL3VlP5chCcdNmWByVK57VVs5fTD4
wh4X6h8xF+D2D1hw89eCzFv5oPpD7IaTqWfsm7NFjD7zWp6NRO6lOjb9SSOuwKlh
28mmETUJuQnno7gVyZAos853r1L8sKaKAZFB6GGhZgFKQlHmMuCnMIEmWC/hrVMV
F8LVF67489JTM/j1h6LwfzOL15hAEnybyfDDlNY7o672SJqGEirX+uUUtoeo5trL
KykuBv8syC78IkpkZ0Q5JJ9PBqJE95AIc8rISMWGMhmj6jDU2lKwcx9Mjzwrm+R3
jwCt3AKt9XmT43+Zxvp52EbEmu5IFgDeCYi3oKByJy/nNZ4ZSanoaa/NZjYBpF0W
ZMv3mgsXjrlN2AEQhFk5U/jslo+6v5BZ9LF6Ef2q3SFmnaAA8uDh/vNlXUZfZHKl
9BeCVGynk7aTfVVBwPEv3LQvlFCTqBF4MMtuwl6mMCdgh8lT/4EJFgvVZ1pJMP+s
/gq9cuT2+i2nZx83WM5qrws6vxp6Upt+jzYkoPeJCn4=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_192_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-OFB,FF7E37B3FEF59C5A65C41D1BEF794605

Qzr8S+Pgm6te7jMIYx3Hdg7gVy9ABeXL8KHpW9DhUBcWrVrfoefWCVnp6CRrXqo7
VU0qiXOzILNeo5GuujeMBU/vKhIFrZBMtM0Cb/CPbxwEWmvkCpdpz9/+EZrIH2kw
oAgXjWC6v5nkO9PQswY0nVPIUm35eYN4rZFyiRlOVVrb94nftkh8XodHEu+dndvj
xuplDO9FgJeDIpyvi23GElsRlrtalHSSjvdKKabuk5XNpdOUnvbn7hbmrdSauwHF
xY4ahm6Ld27FJMxMSLJkWCSCA28D5a0c/CMSFu7qp1zDyRcZrZ2rhBAUZAKcQt9J
jMgu7SLwhHcJNGraVq1BitGxB0O1fK2HbfhP78pbtRI86BiekPCaQnLOAniSm7qZ
5aF4RbU1M2kR39YuLu6ciW6Bg986sH9aoNIPKluK/sVpcqLxLMJx0yeBE4AU8HYC
NNds0tiiGYn2MDyhB0QNZRt5RyPUhmqDli/POq58S420Et7MTItbCI2X9nRyoWJb
01XOtWUecefao/+8qZBs27gR1BSESsXW+d4xegXPoaxmdtSPF7zy+jkmk7Re9rtV
McwotMjIhw1f4Pgc0cKnnVSn2tCDrU7k9XV5SnTcyVwVatz7ThoBF/vhGHdBK+wz
q9GmPx/l/RZpm2syG4rvd8Ofe+rlp00/KyGWF/TQpI5CcYOk9FWTYmcr6fxJzfC7
PhPj4+q8LxTGveaZpg+tLGnm1o7tGviM41evjPE1EvIFCGyqfGmY4vf1Rq51vCbZ
El4w67K9Awvy1pAK+a4NwAckjDXJxN4nWO8k5260ZBIy
-----END RSA PRIVATE KEY-----
`
var testKey_AES_192_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CFB,55C7F8A07BB8292823213057B20F1068

s0resB85a6gc5nFU6iIoN3eC6lGycjL4qyU7/oc/KIfnwRIqnLGCgdds1ZQUu6P7
Ju0WcWf35A9PWCBVDCbvI1aavBFmkKoeVT75vQl294wMUR83Msh8BUd4EmBAOMNb
u/PkYVduPeIhT1JvyW3+O2ZW7MJ8YnpJZ8jlNsmha8th5wc4aedOHDG6bJfFiMXX
Jnqq9fKHRqImZYSuLoqkwWGCvYPkzGvroqf2ZbR/HWj0qK5BpOderxJ0OXYlv3cU
qMwEeMIRr8pdrvmplYPihRlPCZwcMoU3Ksv+e8oLBu8Ub5XIqJwhDs92LXu9Hvam
Jh+mtURFTmX0z4QNa5u2yOAfckeyEbWhR5kbbPjpSVxOaMjSkb1tNd31uNRcrwDY
fhBKln/nUUASPcE+y6QH2f6FVezd0XLXD0s28/3RqMKuKdheIPgX6ujt3/BYPBfQ
FsbZqaP10VjUOtfyTnv7dU2s+PNZt3Z6/mqojH7s9lb+WVDkGwzyFSrXMZOte4Uu
lDdUlhG82pfRtimuoMfcFd7kiL4qQTOlgQMSiBOMEN8r26S1hTfeAebQsr09ZG71
dJC7ERMn6Yt5S88TPHSF/OdjCEsPF1aLazygSjSwhoACX7g7045afZvBQ89kNjuQ
8VZfsBE/rXv8zfBhsvqXovWnxLT8Zc1IDdBAqHWIRPHnd34n+me/GIC2lbQTFU9I
p683q/nFSaqxkWFpNC3ituZ8N6Df95mlP6zOHL0CpqUthqxkBqv1BGT75CNrQ2th
KzyqVofSD5f7x4RlH4XBFLDyItcpNjytcnLbdRiBuLg=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_192_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,2161C430D4CE65BA154A119E38538299

6p2quaycDC6BYv6g1lQa86aSOP5o2m5ZqK45EOukP67Vi35i6+Cn8K1NzhRuabw8
XuJe2IdJ64LkZqPBGQQEyedULML0XB7wMmfcBEisxG1upqmf/pwRuf43tD+P2Lfe
jGqQErJRa9uJF59mDMuM5EG9p7laOK6BTzMsHw7I6ZFlAFPy9h75fhyRUfA2AuF6
Yw5DIxdoM20887btoRc7wmKzdYLKvmLOlsi/r90GccRZeotx3E0nD2f8yRlzlv1f
pUuD+C0FeznTXKDELzg1Zx1mmcUb23rmltnOCj+VFcgbR3WemxWxopnTAMpjAiOG
giKVQToF7hAMA1Uz8ik+Dv2vc7UUp4xIeST9H7QxcsBOYZ/lPD3s2/wjuTckuoJD
OCcIFvs1kzEEQ0MBLWsQr+IgRvKgGcUKabdySivQEkJuQ3YoviZBBbu16O3C+fIW
SIN/alwP6UFBs3FQ1/Rrh4+WZCrz/S1kHHgkvQKtbLfrIS+Hzb7CWoiwQ4w8VGf7
rNTREXj+8+ypbbcGEQpi6lC7eeF0fN00lBaYB3lY6GayJnkxVyal+IMKvm0kA2yi
Kubu/moHRkiYsGZdWDUbqhjb8cVZvJZIDWIaLvenRlXUpJoy8nIGMVOUUX8Rvi7V
rji1VkKLcwM2Y/WM4oYjsTqsRI5JGcbmGjbNUQibHIJtPH0Ribtw2l5cn09JV8Gy
cL27pZk7SMHaBByIrfDFEO5TsAA9jQ8qAZFDKVZFXTA50Cpi5b1iXue/Vpe2GJVt
7Rh0k0coQBIDqzY9TITJPATqkWr1YOfw22BF0nOhjwqtFDl8oSAQBl3ZPUzw1zTL
-----END RSA PRIVATE KEY-----
`

var testKey_AES_128_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CTR,1098F6615FF76BBFC36D6AB8DCF536C4

Ecrm0MZ03G2JGHAUt4sDL4ayiuCYzGsmKl4v4gLnuUcF2/LExs2HMWTjvEWlglvl
LqSW4MyAyKyga1QLTmlAWBHT35WWVPHaHZP4bYBs78+KKdaOtI4RLRCHs2jVla4Z
a2PrpSQA0N8HbVPtvqnamPEh/Oyz+qv0VxsYhRcPiVdLsGll8MMSxJRW7ihblOwJ
yhLE5uM9HDD+2oPoIsreqdvP3tNCsMCI761YItcX56e1Vj70FvFrowLQVCvIeDP2
acwMTUehbVv6PpOSKCvNgs09uX0rHkIJ2gpU1Xux7ChMNBBfdDeWSHW2OonShB0l
sceSb/fLwlXwivdeVzwDr8Jlr/u8f7TkawqMXQI7ummhY3bvYyyhrhX8rZTTsY4A
KYGopPxku5yv9EMPWkXbu8EHUSpXJxGU4FBWsim6iVqKk+qbEzjmddX5KVm2Xvk7
qwbQZQ8JjKfPipTHzL2iDhPja17Z0PoIh2cZNmNh13dDvzSoRnRuzsZCsqSjVLWp
8tWA4PSsvs9Z0fww2rU31It+Rg10s7BvE4b6onyiPCCcHnx4scp6fV45bEhN3vDi
MK8GaT80kC09Fd1GZgObVKk/qo/FCsOIvLInKgOMZ6SyqfM0Jh0dYD7AORSrNQEm
keHhCwJwGbOUpsgjYXLt4TZv2HnMfuAh91SbPci56bRBsH0MaqkuF5HMuIKmSN9K
ryJUnhIYg7vSjd6jeALOYyvBNg5vwlXdyo56Nc/khRC0eIhb3mAOxHeQlwLwezoH
HmZRvXaY9vd3i9q8m2564tVq4Botb1hfG+uQ7e58rrQ=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_128_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-OFB,A9BB7756F20E18D37B48CA1A358C3CDA

oOKtTBFX4QMStx8Bn3494nEcNy9FWomn5JZKgWOeiFir91ibRDeMtO7B1aj1hohO
p8Xw7FvYN//oazGk1AG5W6FIUiBsV7zA72ykw8eq4su4GaatScxbpjIk2zCVUMXX
M2/giO+YFV8dk566GYDRBjRdSk1gwDp83Bi+lqdY/a5W1FEoDXKxFJBzvtzc6kpi
y6uBYHxBAkuWlj0kx6gzpHrhyE9thD7vOcbSTtT6Sslns6f4NDx/RrDHIGTIRYLz
yOUy9Ci4d86PeyQ5WHkCuXAoe0aLX6OjrnGJw2c//Vy1fcP6AYce+6AaNJ2/BQjr
EbywWmcOi3389fc5uCrcKQSzSc+Y8Q1IWSutlpJfz0H8ZBttf25UKUEWZGwBjTtH
7pHS7AAiTOwGo1R7bB0PwGP658FZLJwy4zf08KdtguDHGFXgWYZ4f6wCgn+S6+4d
nlrjPWkZV1GoZjZEc5Fw1MBFvQ+e1a98FjgV1dRSSGlbyZ55N+bd/drsoGZJUgeI
aMlr45okne94c6CnYc1PkFCA3mKSOGx3sRVtzgKDyb9lr3t3m+9iCnmTJVfNfy8F
RB/yNPpotccMUqoWJlMhvF8pDRU4iXd7y8J+s9ktcSYOJ3NQS7cAPOV8XVcvfbtr
dg+HDc7Bsj4BquslwxaChxvNLfEFJxqixot41MjrpQZS52Nv7P0pWWGD85rRAsxx
blXNVyALUPAUM59RzLmk1tmn3ucxEFe+n/1ss13HbXygonqAnk73fFE4TqjsjKow
/QQx1/NHpsKEGfTaEXgQPpTTaGoYmiVgcLkTeWNLrZA=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_128_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CFB,35F0FFB8D97ECD6D69F73B28D98A6BB7

3wf0Vj9bz568z2J0iTKdr56qoAe5NgDaN3EdMPnPQ16xAwlztbE9VPtx2zmQ/RK9
h/JZJbtWZel8SbvO9xRAuJXe/20YVvZ2zsJo3FBymjsgTF79PpQj/iixpmajNVBM
nrkNDSJ/B/4cAkDx3/4pGupy3g104uh8JZFjZCHxCwhiU/ATw67JWWpt5k9DzwHX
BuYdzzGwzSkTCTEqXDxedGfns+Wo177EcyBWlWWqAieHTfXepUgOyz9JS1JU0GSv
RhhjGDocOciQMBLSqho+hFJYzu6fB/TU0v04Q+yhHWt7PeSWOpWmG9ObuL2iMVpo
REPRLTkiwwTXhWmd4xODJ3yae2moRwk2hWtSK4TZgsIHY75JmLZTpqB1INMgVA5j
CWHCZv4CU6yeLtcJBBsDm11uk2Av7PInDoopQWpmtnWs7QiCQZeL0EPFYcx/qz0q
QIF82iHFgSeSXJ0hSsjTNzzjLvAw9/3VABcd0PaSiJN7qjNAH1Opi32EVmuGlV5j
CofMEja94bDowTEEDDR8kKnSCd5CsiglSLlWZ014XgSpGZylE4B/R43PFvKSradD
VjEia0sJl1AfIxa3upWkd8nequoddeOVU+Xklzkr0VpIBHomSEdOdyvHatTPPWzx
II9th5ifLh5kqgKx4ruR9pSsoX5A+6WnUecvF+x0T7Qt2D9NA1qaVju8Fpw+YEJQ
fbavDLrIGxjTi+Hebc14oXK2qsKli+pV3r9We94GWNPj035aT0sDdx+5IxLH6ule
rXQarl3KI5nheAON9KJI+f0U4S7vYfC3oFgwdpyVee4=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_128_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6C2D041C3FC6BA1BA1A742CD0C68D90E

fJn49F195ATNhI4OiqdbsxB/6CD4xl8XjTjb5IzlP6pvM+T2O7ZOYeEaJHUGdxoC
KOAxrqJrw1TzWfPY04JU9joH1DekGm0ugzih+AEGIhNpxUE+eTt1Yf88/9rd71kC
l7SB2UyeFXIPGfMYlPSzTHikO8MOL50N46DYpFJLHNh6vL6ZYMNpkWyVBiuuVrar
ap5wiVL5ch2i3U0xorvjau6J1tdAu0w5p3LhzofZDIvwkbXPzSQk7dW3l1g9GrZH
fKFO64Qe0u+Y3wexD3AH4SEjTTXan5leoxwW93Ik0/yFW3aORrA4anVbiW5nFqwV
iHonZIAye9KaXOqOlI1R7kCI50UyVkUP0I9Uvmr5elRM74gMVnZhS9CeRgP7UOMC
Q50kmXTBmosgjI4QWUq1a7pxyQFBd5ruD7WP43od+vKr5Swa0a/fJTc7XqvRhf8B
D+Ysr6+g+jNMasbzFY4Jc06TW/0zPnPszbSR9WWkXis7DuRotmU83bqRl5w+rFZs
1Z26xqgg3vMvFBI8Bf7Kofi2YuRkBj5zYqqgB2R3WZUzW65X9pv1CPIf5O6jACn5
mCI++Wqw8gIeiwvO4bXCZJ1mtCWO/G+X6jga1Pc9Q8OW8Az2ddsJl5htogxcoPXV
KjdKnYAKD+2mM418KkZhStHEUky827pdOj3BNBE4BjzI3fjIuLQ96qltFbBuW47M
ikpRepojODGDwNKqta9kLTNCOxrNPjhKhWb3YRv7xpppSgP0v66/ZkoeutET07lK
WoAagYh7iYIQRzgwFTIMcu8D7dHHYtseW/QHKbfOuFI=
-----END RSA PRIVATE KEY-----
`

var testKey_SM4_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: SM4-CBC,30c634095fbc029f505ab9b86652a1d8

4GlsZT8c/RJN53+3clkNX8G4dNRuGiBtKEqI1HyC/Qm6ckrlsz+jKiNZWy7Wf4b7
FgO5pzvggFeKXRHIJLIjQ10iujHlCES9LwhpAU0u50qNkmXAHroFTWwwmOQw4B1j
Bnlr4ezcB3OaWgx4VJyhccxMv14qRCeujZAvr2iizfz5pp7PNcTtfrePABRKF+KJ
UdG0ROzNMRPZnKKFxadoaR6hFjbOfwXbbXrRsLpK0Mmd1/tdnk+vuLqt1XQRF/pt
MFNEehlaqxoVojtbOqgIama72f6yIkukiyJyjHIM6xz9U+MNt+loZuZRF1VFetEp
6KISsBu2emAtp9/xD0X7cIwkjFLYvy5L9ubVJxkT727mySEAU/u5uSvwvVWzcEX+
lhmGk6b0DrRdl53socSjCl2dprnhaQSWpmp5wvON8XKJtkFoSisrzKaVh4DRi2ch
qENLI1pnCwu9agyWkBVUpZamkhw7fuTfL2sqVUaCjRpVRzdtxcPAOCp2vyyIOKG2
A8C0YEfAus3slj395mcxsIJlSE/hl77oegSHa+3FylDqXt4mrdqUliia4VgrHNqK
JL674mz+fmupHoSBo9fjkqGrNTRXpm1gKuxQY08+e9evZ5v1IrhjdIbHep79JQHC
lxgTXddL/5ev7bhK+eTPGyXtswdJpuyOiyy3Z5m/d20lwxv7+pBSVVHxfBzrsNf7
S4P8VHPnam8F2tyltN+8dtPRJPFgWqUDJLKsYsBywAfZwx0i940ix1RH7ZvPpkPO
dKsLNZLf4bO9L+N5E1Gy5zhzdWOO6Fb09RlBvuS+IoIzdtWdEoMAs7LBtuTx4aUG
-----END RSA PRIVATE KEY-----
`
var testKey_SM4_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: SM4-CTR,9c005970fccf7643273eb33289c6897e

po3oblCZGTPfO5GjiBOS1/yTP8iNC09el4FFp4rHiYmaN/9kKwM0vgBh7g2PsG87
fkqrWbLJM8RFIj5fsjzSFjzVTeomBuxoyLTUTAkEZ67Q4rfB2wql5M1qyfk9Q8iU
ZMTLVoR0UJzLMOB3ln83LD2c35jfGdCURVPtq2kT1r/LiA+OQMfZpLYXNLCGdF2Q
LFQmxWqmeM3ITGpygYKla65uosGqFhpCPOCVGHmvjcVlzt4sjpq61g/stEHISP7s
4ai8tD8je/m8ufkBtF89xnPE98sT1NFusKtnu1VgfI9ny8iaRgEQwBbL00ewJoED
XdzliF2TSreu7szuoXySPWl4/zr7Vb6OUlN9XwOZAOUv5WKTHME1rKHcIu8LibdK
5RcZb35aT+4SrcEocxNZoQ6/wyhvq8wNnzpJWx+JS9bLeleNZL/3csNomS+HymCq
t0hwX1RnR2foz7pcTUkLMYvXO+N0VYCIc5QEonueIkZmhj6UWtb8FI6yQaOVrlVP
jMDVuxlwYdI71LUW2ID6ywoggdcMJulbCdIivNwANJtvWEFvFFu4DrZsyPEYa1Fi
OWZjut8AjIc6fiR3bkA8TnqSQ9R6dh0JooDFLOHIhoGml4q4PUwvOkG3sP8EkKaj
TKFYv0dnRkraqKdSC2MG+7Wm/NQJxQ30y+ZkVgeLvrgqMhsr09KAJEGy6cAHorX2
tJpvHiQXiWu9wRfLl6Gt8JAGwPGSxF8SKHE1Vh5Op1jn5it4m9rVxG6ftGz3AGW6
4R5ObWSBwcNS8l183p3WVPE7S3nVzEsdBJ/fdVSEuvXJrA==
-----END RSA PRIVATE KEY-----
`
var testKey_SM4_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: SM4-OFB,033d2d8d10af43959c832ec1c77a5004

iH7Lnc2v24zw54Iuqr+5jU541yGWbTR8LL92bfYInGYc+igqvd0D2CIlfjZqLmIn
pUjlgFSUXt5LT9aneKMXLsVT1IAIXkAr0GbZNZiHvqjiqicvgt221aqEC4B53RoZ
aFzh1TcRGFdDooygj36GH5bz3hodW7BOB7j2sAhdC/I0iaRPdJhUfbcQeFjxpJeI
5vlA69pxshfZAdTKHA5M3QBOLgxW9uiHxJ6+SYaznx+XmvbhIX9FyBuNxTKNUFvJ
85sWliVHWcyWVyv1+wmBDH1FsehAIBQiRImdTt5hStN6V+MZYbdx4M2imq9ErMXG
jx7ztpmyfzj97JtILjIRp3jPgLOzrJ6sD/rT3yOtjfLo6xoRzVa72kinxTmlFVNE
xEVm1kYweztIX2H8p+BY/WKxxfKMQQy1El3mf05A6tgievv4I/VnnEeViSay8ovy
Kp1x/3a+4zONm8sNDO8kgu2BEaKuEuQ8Q2DoedCF75cbM6ovs7davRAq10KCh7xV
5RlpzP4EbaeoZ0c8IvNN5ixBhFkmUn+5blaH1YOsOvavSbprbOmMTeHuoLYjE9eM
cogFrVaUwLl8ylP1zxKTCWuN7he4/mI9iw783nxwt3AJF/KB7W7FVYiLA4WuRcQm
u70cZ2QYY0zuxAOA/OaHajRIAsukO+lJHwcq6OSJv3Q13zROqzoJm8ETbpTpjr8t
FAq53kLhPJzV4W8+HyrZwKbE8Pve2fbNj3ukF8FsAdqAweDzPL+Ulh/VqA+wHKpo
aohKRP2KASgYSx+wUyibxkER6XEQZc11jVajreaqNNR15g==
-----END RSA PRIVATE KEY-----
`
var testKey_SM4_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: SM4-CFB,9cbec1ca07cb385c95f9e668a8e20100

fxMzQ5MeKagVz3kDaqjR/kQ6Ilq5F68gsL5L1FoYbJEGphaeY6wWCy9tdUpdCj1h
n1AhvuOg0BaCX/MxjDjen70a1J2+izKDDa9LE9gIyPkAnQcJ52wyBMvlAd/n/BkK
mCW1Zri9SoN1lvy/mhVPFzL+8JELmfH+OfLQ1UkMt31U7OB4HNY+Fxxzq5pFNBHe
T3sbFbZdxI6kwhMo3XkrQgXttRTQhGSskp6lpr18gjWqmmzzI8DDbZZRWkzTWEkF
8QcPG0GEKJsVItVFBuRW8+acrc7B3v+Ervz390qRaiEniuEqWpEKWJ9B58VV9cxy
DViyfNKIkW3psF6sDQXjeAm+F3njZikLnbJLrBiMjz58tujzlfhKZkrnnfAsJDgX
Ost8I0MRFedioos6QGgycbR0ybODW78aPOx0y7/GVb7WcTBxDsdQxvIfnR9IFjLH
0BSaP+6EFGL1HNJoD9GVqChi99fY4ml2qc8kBiACYmSypseN0tqqf9MiVsysvioB
VTv29qf4DLeiUm+pp4cdBP4dMoeixDwZEn0fzR5B508qhrESgKoowiW/mJScmNu5
gdPpA3c7iTaDJEJACt/gkod9IRmgBXMxqQve4Qc6rIs/BIgsMEDtLliu3E7jX8yg
L24KFKwZoOEUja7b9eBZXlViE01MQ4LoUpCnrWM8Ihj/DUjTur9umJhmuHLcohmF
oNygEmBTEtQ4DdhrKlCxWu5DfUGuU0FCWzEXPrOZ4gZ/VNg9rJgO/9TMmSzlztJd
odNbWbLvU/aGnPj9eupOVmyf+mpy7iea6VXgXDiMIbP5hw==
-----END RSA PRIVATE KEY-----
`

var testKey_Grasshopper_CBC = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: GRASSHOPPER-CBC,c5a38a0348b456991f6da17f41616ba3

VqPWTXK/m9ZaUrWdJktSh1SSZSfNXjtcbuAE8NO3okQReyObg2Rq+0nBwGSVqXJr
fHK9sr9t718lUcthfHldnDVOa168AwrjjG64pvNraA/QFFndiT8xJV9zlnlv2R2O
ejjqyT8Pj8Uzw93Dhew+EiCWHk7ow4075O65JJu6LSjY43y7JZ4hX1mfZsch3+V9
T061PUwBlsLUmesCH0gnpUizD3Syyy68IjpENw1gskm+GlHkaEL3JhlOo68NTKn+
Acau2iCpjy3Gt/N2x8TypZP+5J+N5YIRKzTjE3vuCnOcmWzFyf123foQSK5K8KhH
UuMF28rrQ+x0s46es8iJyP546PEFduY5fdcxfF/Iwpv8SjXWYbhQ7FXjk6MKH84V
vCDmb682Ppegf+h6W4MZhw+3r/89YdVEp5og0qB6T8vJEQhsZLXTsfMfiLh2yvFK
rZUrPm8RosWyNCpONTsx8P2jacMKP3uNZ5NDBFORPre5h+ntNiW9R9FYkm8Hh4mT
QmCtJ7zYNRXZdPLiOCHjGeMUa6yCCmsSdto3qjLzVN4esDdlwsawa5XDR1QmCEpa
tKru9ZOorwiRKqJYj8I40hff0+F3W/FVTenpKZmWlUvmZ0PxF4x0gfTGKgjULLYR
JQBWmzKeQ7MSkW1QeaC4RqHZ9pXSzLfU9fW2CQ0tI5OSWgXiNWMWV1BcAY6JNIn+
fPE5RCDM2sR9u+/4iqKE7U7v3lOAXqxT6flkgJumccfy0OU/PmgUtvJ81XEdRHuT
b+cNhX7hB/N3svTWtDiVIFfSrAWfen///TNJ2iJozikcdKM3tzFxPZTHCQZgbs2w
-----END RSA PRIVATE KEY-----
`
var testKey_Grasshopper_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: GRASSHOPPER-CTR,943f5df1163f4116cfd9da0fdeeda45f

VOvdVcOabJO8s5BpjJNKyU1KjmJyIkkiRzI2Qze7omEbxBbsrz6W9xUMV9E7pq6G
wmqbEtdZnVbUs7JrcqB5+6bMtRAnUw8s2yKTH1c2qz2HyP9IivOQIzNnvttkpmns
iuFZ2Rt8AkHsxjGj4KRLWF5C08wMbFcPD0V3OAB8X4RgxpaNNxx5RqqaCc/nTWij
XV83dXqrOORPtbUPC9qv9mVhUrlU+oE1S7y0yvSlaoEgw6GwnIJO6MzRTcMZCACH
mTRt27Dlqi0aPhsHv4tJiinI92k2UBuMCmHAPn3n0XYChlmm33SrwcnD1dbvsDTN
8CX7SVoiI1wj5O7qhYyvSaCiHlABFWMON6MFRpR3dL6WDwiSfPL+v6b2EIX4Wlei
tlHTxFukfs2fLy1kQK6f2+U0W0QJgqlHfJ4Y/AAFBhOBDsw6IiAXq+F+gyh5MD+6
Gf19sL+S+a6Xtv3LR810GJzlOm/zUr4Z+KI3TA8UDB3QA6hgqEY6u5ecayz6Stg6
/pjWNtyP1E+xUULxkI+ruVCdMni9LPwJI+dheQ1yoMG4qwG1+qhxLvL9FvI/M8uJ
X7wBSsGWNhIatRT27Zioz0GJAlgfg2yDY2it48kbwxlEfaghvK95PTf0LTIshLmG
a8qPS1fq8YwnjMre3GHIUSXbZsq3AA+F/0WUDDZxRL8kh5L+oOHDqtPOg6Y66+NJ
hZp/xSn88joWY67ANmosX09Gf0WaK5BXxUWwH8opVI+d0doVGTaVjQdWinNkS8cx
QH/4ueDy4+ogKy/nplnnXqe4BHeXjwtXzR+vZ/+vTJTuVg==
-----END RSA PRIVATE KEY-----
`
var testKey_Grasshopper_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: GRASSHOPPER-OFB,67941cfad62091dbb97af6146ef85576

mQJ7symYdMS5iSpBrsE78i044FOfKpMsCNCamYEBuIDh5OWE2ZRxUCrlexxm4oMQ
9Zs6At/JD8SCKJ/wpcAff/ZhyKAXBRgrWlcBMe+D6pVIYPLj5baOdba+7aiQHZeB
eIWoQA2RghQ9axfcdudPZHjaYvhQ3bXdusCHcl/RmbHe/5PWz4bbQ9uJLow763Sl
xw3UQ2f5mPMbw2qmV+UGV8ufZ/e/tlQdChfs7lKZH6zxEWPRpXiAMdRDcx7KHnso
GSN0Mz3neR5yMvE4m5HqjH0Y1wztB2sUCrXex//hoFwX2B2aTpvCOd/bGzCLC+HT
ZHjCyCfXaMAEgT/4VvXRmnZ3En+/A+yr1CbRJTOCX2L2e4JXARjK1/6kSdSBMJEe
iPl+kkSf9RbrIWsUlrWbldg5gMBivxd2DWW+jxx05C/y4zgFzjiI6txloiOkGysS
MAet/FP9kaleJ8zCmgoCRS9URfjkM0RspgW3YxN1jFW9IP40mDAlmDYHdPV55iMY
rNqiqm50LqPp4SRLxNtAUKlmnde1US8X72HlikOhpBecBi1G9RxreWwMr70Niw81
gArnmqjhXM0XsAOIPxIr80oBH5dSkeyVwgNCM8vF2bXALdymFrOM2yNykyqOaVXt
zef6azVAd/aTISqmM1fUb+CtA7LVw7ZCIlvEaf/VFAnMGHhfNrwpwGc5hiVlCUy2
S21CcAmfL0Ov5mQuaL359ysUDu5GLoFbp4tn8ZYplQnnNjEoRrzurlXUDdixemRW
AATdgXrNCVOYN7VuFEAsiLYTwUcsQsD9fAL13kbShlHJ/A==
-----END RSA PRIVATE KEY-----
`
var testKey_Grasshopper_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: GRASSHOPPER-CFB,5c2b8059ea61176cf26525b3921e4322

U2cHBpoBGrOxunW6POfOAc7qvrlNUr6dCjOWZgu/hRD9rpzxv3OduCVoopO6fwdq
jsQ9gTda9syusdosRXDkt4oyzANC8wquLFM7H/e2q3gwHF9XZWQw69hSWjS5kuvk
AZOIch3hu744w8XXy2IgRCdPW+TR6edgXNBMwhU5aEf+ohTKa/nS5o5QbdHAu14L
VLiZLDBbRMiGaJq23R9CSWPr2JSF+hhhUluQivFnPFJ+73C1dDDWcHXinr+NfraK
TdK0JMZwRxo883dGuwezPPaA/pL15sacXzN1splXwE9d5xGnwRcETmv5kiyE+X3/
+xo63fwGsUGCZvwX/rEAE9VWq7yjq/oHoLMAIdYDyCbH8PkNvo/rzAr086aDZjFk
r2pbWBtMtv3SrlJLZVkjgJb5MUKtDDW3VdGGcZmq6GNRwv5cGO4T5nLwClYVn78L
t76UafKjtU9yAbmdpiAQ2PSTpPRWZiHeTflQP+1QG7lgYUlVy9MmgcSRfnLwrDl9
IASEorl6rF/RhQK5fSOeHLLDwFS5j/PmFqusjNAvxg/mYz1wsw4vUQ4pF1dqka4l
Ioe0rxPX2l6oADBv1EFwB7cJa0E3NW/0OAIwE5y77TFShx0Whux3k1XL8sj3RSIT
Azr0FpS/I7CgYM2p1WX9bCdxY9jhwONCBDUGdfmiy7gRfSNBOuk/mSIhvvpQNZdS
QO0RAe4sutURdz9SWi085hE9qyQn6IsCegO+DochsRpF4e0WryuBjbZqHr80jh5n
oTekIprTtrfsayNZwxO1oblkgA8PlswN/ehJyt/GztnpYQ==
-----END RSA PRIVATE KEY-----
`

func Test_Check_PEMBlock(t *testing.T) {
    t.Run("Grasshopper_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_Grasshopper_CBC)
    })
    t.Run("Grasshopper_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_Grasshopper_CTR)
    })
    t.Run("Grasshopper_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_Grasshopper_OFB)
    })
    t.Run("Grasshopper_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_Grasshopper_CFB)
    })

    t.Run("SM4_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_SM4_CBC)
    })
    t.Run("SM4_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_SM4_CTR)
    })
    t.Run("SM4_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_SM4_OFB)
    })
    t.Run("SM4_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_SM4_CFB)
    })

    t.Run("DES_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_CTR)
    })
    t.Run("DES_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_OFB)
    })
    t.Run("DES_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_CFB)
    })
    t.Run("DES_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_CBC)
    })

    t.Run("DESEDE3_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DESEDE3_CFB)
    })
    t.Run("DESEDE3_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DESEDE3_OFB)
    })
    t.Run("DESEDE3_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DESEDE3_CTR)
    })
    t.Run("DESEDE3_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DESEDE3_CBC)
    })

    t.Run("AES_256_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_CTR)
    })
    t.Run("AES_256_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_OFB)
    })
    t.Run("AES_256_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_CFB)
    })
    t.Run("AES_256_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_CBC)
    })

    t.Run("AES_192_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_CTR)
    })
    t.Run("AES_192_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_OFB)
    })
    t.Run("AES_192_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_CFB)
    })
    t.Run("AES_192_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_CBC)
    })

    t.Run("AES_128_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_CTR)
    })
    t.Run("AES_128_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_OFB)
    })
    t.Run("AES_128_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_CFB)
    })
    t.Run("AES_128_CBC", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_CBC)
    })
}

var testKeyOldKey = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CFB,FEE6BA57503D765BC6D87BC6954A0D72

bq7Nbbr5BF8Me+OXceRQQAc/S3wcD6Q9XLQgHZpwulLkw780ooTU5C51d/4JmPcM
NZDo35EPjCG4jb2wEvdWItpn7nF3LMnTOvJfcpH03NbgNfbLgn+jvckkU1ehOPoi
UHgww/4jjEGeKRTefzbjxEg4rD2aRuxe34yR8GlCOR39UxdziIQytxPvRl/Ad184
+QeqFb6cW2MgMUPkAL/PA4H1TfSg6xCET5ewMhgHTTaE9sEmDYtlxCVEkhLTr21O
avMHvLgQS+iQrE4h3iJ9jvWWsUUYTIfCpNrN0dujClX/RPETfiNhUihHXasA//qh
+0wBh3zroF/+2TEYXwPOJyHBKULEgUBxm8mdSlHLf93mkMpYs6josC3XthpPzX46
P2nC2Pt7lzs5MRNIMlj4DWCODOzuDphUJ88Gt+g5SCOl05fqRka5Qy5vSWc3v6/3
UJI9yj+eNFF7d0TjW3saMF4m7x206q90LL2d3gN4hNA2a+yVTiUQ6/HIlAebffTh
RWptkznl0BSJkvUu+jon16KnPYQvuyFiI6KN1GUKL3a58OmfNljmNYyY9dOjjT0D
IrHJbDgyuwLcQ2WhafdTDWt5Zj2U1vh2GbkNAxQzljbDku3l5wvaJvSQSHK+k2uI
0pHc3RENOFZ751b7A+H23Y7V/Kqi9tWfCqFo0Ybdc8kah1a1+zyxSrq7FEhUG8ja
EJI6g3hykcWb6Xv6g4qCNxt93nTyPIxeJsOhCiValjJGT5DxzCGjcwWKh0xCTAOF
UR9uChIsW6/OIOevnvffncQoPNOLZx8XorAdD8ABtg==
-----END RSA PRIVATE KEY-----
`

func TestEncryptPEMBlock(t *testing.T) {
    block, _ := pem.Decode([]byte(testKeyOldKey))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", bys, []byte("123"), CipherDESEDE3CBC)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if false {
        newkeyData := pem.EncodeToMemory(enblock)
        t.Error("encrypt data: \r\n", string(newkeyData))
    }
}

func Test_EncryptMake(t *testing.T) {
    t.Run("CipherSM4CBC", func(t *testing.T) {
        test_EncryptMake(t, CipherSM4CBC)
    })
    t.Run("CipherSM4CFB", func(t *testing.T) {
        test_EncryptMake(t, CipherSM4CFB)
    })
    t.Run("CipherSM4OFB", func(t *testing.T) {
        test_EncryptMake(t, CipherSM4OFB)
    })
    t.Run("CipherSM4CTR", func(t *testing.T) {
        test_EncryptMake(t, CipherSM4CTR)
    })

    t.Run("CipherGrasshopperCBC", func(t *testing.T) {
        test_EncryptMake(t, CipherGrasshopperCBC)
    })
    t.Run("CipherGrasshopperCFB", func(t *testing.T) {
        test_EncryptMake(t, CipherGrasshopperCFB)
    })
    t.Run("CipherGrasshopperOFB", func(t *testing.T) {
        test_EncryptMake(t, CipherGrasshopperOFB)
    })
    t.Run("CipherGrasshopperCTR", func(t *testing.T) {
        test_EncryptMake(t, CipherGrasshopperCTR)
    })
}

func test_EncryptMake(t *testing.T, cip Cipher) {
    password := []byte("123")

    block1, _ := pem.Decode([]byte(testKey_DESEDE3_CFB))

    bys, err := DecryptPEMBlock(block1, password)
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    block, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", bys, password, cip)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(block.Bytes) == 0 {
        t.Error("EncryptMake error")
    }
}
