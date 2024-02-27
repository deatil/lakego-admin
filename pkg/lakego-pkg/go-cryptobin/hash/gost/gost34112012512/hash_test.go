package gost34112012512

import (
    "fmt"
    "testing"
    "crypto/hmac"
    "encoding/hex"
)

func Test_Check(t *testing.T) {
    in := []byte("gost34112012512-asdfg")
    check := "f6e5e348001a4ee3a1299c5283ddae617655353fcfc3d79c81f9c01470bbef58075b0514c0b03187a3c1bb7a24383664abac0fbc2019555ec65b9a7d972bf864"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}

func Test_Check_2(t *testing.T) {
    in, _ := hex.DecodeString("0126bdb87800af214341456563780100")
    key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    check := "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"

    mac := hmac.New(New, key)
    mac.Write(in)

    out := mac.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check 2 error. got %x, want %s", out, check)
    }
}

func reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}

func Test_Check_Vectors(t *testing.T) {
    t.Run("test_m1", func(t *testing.T) {
        in, _ := hex.DecodeString("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
        check := "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"

        h := New()
        h.Write(reverse(in))
        out := h.Sum(nil)

        if fmt.Sprintf("%x", reverse(out)) != check {
            t.Errorf("Check_Vectors error. got %x, want %s", out, check)
        }
    })
}
