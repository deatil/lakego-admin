package base_elliptic

import (
    "math/big"
    "strings"
)

// copy bit.Int
func c(x *big.Int) *big.Int {
    return new(big.Int).Set(x)
}

// Fx to big.Int
// f = [233, 74, 0] when x^233 +  x^74 + 1
// f = [283, 12, 7, 5, 0] when x^283 +  x^12 +  x^7 +  x^5 + 1
func F(f ...int) *big.Int {
    ret := new(big.Int)
    for _, v := range f {
        tmp := big.NewInt(1)
        tmp.Lsh(tmp, uint(v))

        ret.Add(ret, tmp)
    }

    return ret
}

func h(s string) string {
    var sb strings.Builder
    sb.Grow(len(s))
    s = strings.TrimPrefix(s, "0x")
    for _, c := range s {
        if '0' <= c && c <= '9' {
            sb.WriteRune(c)
        } else if 'a' <= c && c <= 'f' {
            sb.WriteRune(c)
        } else if 'A' <= c && c <= 'F' {
            sb.WriteRune(c)
        }
    }

    return sb.String()
}

// hex to *big.Int
func HI(s string) *big.Int {
    s = h(s)
    if s == "" {
        return new(big.Int)
    }
    result, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic(s)
    }
    return result
}
