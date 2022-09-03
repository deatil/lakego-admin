package base58

import (
    "math/big"
)

var bigRadix = [...]*big.Int{
    big.NewInt(0),
    big.NewInt(58),
    big.NewInt(58 * 58),
    big.NewInt(58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
    bigRadix10,
}

var bigRadix10 = big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58) // 58^10

// 解析
func Decode(b string) []byte {
    answer := big.NewInt(0)
    scratch := new(big.Int)

    for t := b; len(t) > 0; {
        n := len(t)
        if n > 10 {
            n = 10
        }

        total := uint64(0)
        for _, v := range t[:n] {
            tmp := b58[v]
            if tmp == 255 {
                return []byte("")
            }
            total = total*58 + uint64(tmp)
        }

        answer.Mul(answer, bigRadix[n])
        scratch.SetUint64(total)
        answer.Add(answer, scratch)

        t = t[n:]
    }

    tmpval := answer.Bytes()

    var numZeros int
    for numZeros = 0; numZeros < len(b); numZeros++ {
        if b[numZeros] != alphabetIdx0 {
            break
        }
    }
    flen := numZeros + len(tmpval)
    val := make([]byte, flen)
    copy(val[numZeros:], tmpval)

    return val
}

// 编码
func Encode(b []byte) string {
    x := new(big.Int)
    x.SetBytes(b)

    maxlen := int(float64(len(b))*1.365658237309761) + 1
    answer := make([]byte, 0, maxlen)
    mod := new(big.Int)

    for x.Sign() > 0 {
        x.DivMod(x, bigRadix10, mod)
        if x.Sign() == 0 {
            m := mod.Int64()
            for m > 0 {
                answer = append(answer, alphabet[m%58])
                m /= 58
            }
        } else {
            m := mod.Int64()
            for i := 0; i < 10; i++ {
                answer = append(answer, alphabet[m%58])
                m /= 58
            }
        }
    }

    for _, i := range b {
        if i != 0 {
            break
        }

        answer = append(answer, alphabetIdx0)
    }

    alen := len(answer)
    for i := 0; i < alen/2; i++ {
        answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
    }

    return string(answer)
}
