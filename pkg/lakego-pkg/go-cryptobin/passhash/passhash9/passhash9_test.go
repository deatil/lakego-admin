package passhash9

import (
    "testing"
    "crypto/rand"
)

func Test_GenerateHash(t *testing.T) {
    t.Run("HMAC(SHA-1)", func(t *testing.T) {
        test_GenerateHash(t, "Password", 0)
    })
    t.Run("HMAC(SHA-256)", func(t *testing.T) {
        test_GenerateHash(t, "Password", 1)
    })
    t.Run("CMAC(Blowfish)", func(t *testing.T) {
        test_GenerateHash(t, "Password", 2)
    })
    t.Run("HMAC(SHA-384)", func(t *testing.T) {
        test_GenerateHash(t, "Password", 3)
    })
    t.Run("HMAC(SHA-512)", func(t *testing.T) {
        test_GenerateHash(t, "Password", 4)
    })
}

func test_GenerateHash(t *testing.T, pass string, algId int) {
    hashed := GenerateHash(rand.Reader, pass, 256, algId)
    if hashed == "" {
        t.Fatal("GenerateHash fail")
    }

    res := CompareHash("Password", hashed)
    if !res {
        t.Fatal("CompareHash fail")
    }
}

func Test_Hash_Check(t *testing.T) {
    tests := []struct {
        name string
        pass string
        hash string
    }{
        {
            "HMAC(SHA-1)",
            "Password",
            "$9$AAEAG6G1zTZTQTA8Rqo8RQqiV/qXUaSaftN2cGO4/D7sTUI6RQ1M",
        },
        {
            "HMAC(SHA-256)",
            "Password",
            "$9$AQEAgXbLtftzszam4DtVGL0GDvPvfHPFBlOK8l08aj/HrV6QL+kL",
        },
        {
            "CMAC(Blowfish)",
            "Password",
            "$9$AgEAk3M8caQe09voMoojHMVvP8m2j9/xaifonSZQyBr4Cvjc+Agm",
        },
        {
            "HMAC(SHA-384)",
            "Password",
            "$9$AwEAvy2fBBQjJXL0kK+iSrA/fFDFnqpRZpBq/cdAq+G9vTNXpcBu",
        },
        {
            "HMAC(SHA-512)",
            "Password",
            "$9$BAEAbDx63DjGjc2yvwyENRZ1OvW0PnnO+92dzmONbVTzgAyjcZA5",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            res := CompareHash(tt.pass, tt.hash)
            if !res {
                t.Error("CompareHash fail")
            }
        })
    }
}

func Test_IsAlgSupported(t *testing.T) {
    if IsAlgSupported(15) {
        t.Error("15 should not exists")
    }

    if !IsAlgSupported(0) {
        t.Error("0 should exists")
    }
    if !IsAlgSupported(1) {
        t.Error("1 should exists")
    }
    if !IsAlgSupported(2) {
        t.Error("2 should exists")
    }
    if !IsAlgSupported(3) {
        t.Error("3 should exists")
    }
    if !IsAlgSupported(4) {
        t.Error("4 should exists")
    }
}
