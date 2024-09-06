package passhash9

import (
    "testing"
    "crypto/rand"
    "encoding/hex"
)

func fromHex(s string) string {
    h, _ := hex.DecodeString(s)
    return string(h)
}

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
    hashed := GenerateHash(rand.Reader, pass, 102, algId)
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
            "$9$AABm8neTVueMIcw/lpRfjcWuBYgxqEET5SwIRvThHB6B5na1eDKg",
        },
        {
            "HMAC(SHA-256)",
            "Password",
            "$9$AQBmQiUUX3+Awvd4CZFHdNR0F+MGs5IUn80L4laPfHuzbcWNio46",
        },
        {
            "CMAC(Blowfish)",
            "Password",
            "$9$AgBmYber/Sjp3FtR7rlLGFBPU5h9Z45XjGXsuC7DEfdaJ/SOPz6q",
        },
        {
            "HMAC(SHA-384)",
            "Password",
            "$9$AwBmCShNC5/K7DB4XzBwbewTt6+2YxAytIijohsrP47xDIDkH5hP",
        },
        {
            "HMAC(SHA-512)",
            "Password",
            "$9$BABmGBCpRZcVEckaD50QAy/EagypgMDVJ6OXPHquMpiBxT8/Pzj7",
        },

        {
            "HMAC(SHA-1) algId 0",
            fromHex("736563726574"),
            "$9$AAAKhiHXTIUhNhbegwBXJvk03XXJdzFMy+i3GFMIBYKtthTTmXZA",
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
