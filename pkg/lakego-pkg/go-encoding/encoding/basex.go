package encoding

import (
    "bytes"
    "errors"
    "math/big"
)

// 构造函数
// Example alphabets:
//   - base2: 01
//   - base16: 0123456789abcdef
//   - base32: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
//   - base58: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
//   - base62: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
func NewBasex(alphabet string) Basex {
    runes := []rune(alphabet)
    runeMap := make(map[rune]int)

    basex := Basex{}

    for i := 0; i < len(runes); i++ {
        if _, ok := runeMap[runes[i]]; ok {
            basex.Error = errors.New("Ambiguous alphabet.")
            return basex
        }

        runeMap[runes[i]] = i
    }

    basex.base = big.NewInt(int64(len(runes)))
    basex.alphabet = runes
    basex.alphabetMap = runeMap

    return basex
}

// Basex
type Basex struct {
    base        *big.Int
    alphabet    []rune
    alphabetMap map[rune]int

    Error       error
}

// 编码
func (this Basex) Encode(source []byte) string {
    if len(source) == 0 {
        return ""
    }

    var (
        res bytes.Buffer
        k   = 0
    )
    for ; source[k] == 0 && k < len(source)-1; k++ {
        res.WriteRune(this.alphabet[0])
    }

    var (
        mod big.Int
        sourceInt = new(big.Int).SetBytes(source)
    )

    for sourceInt.Uint64() > 0 {
        sourceInt.DivMod(sourceInt, this.base, &mod)
        res.WriteRune(this.alphabet[mod.Uint64()])
    }

    var (
        buf = res.Bytes()
        j   = len(buf) - 1
    )

    for k < j {
        buf[k], buf[j] = buf[j], buf[k]
        k++
        j--
    }

    return string(buf)
}

// 解码
func (this Basex) Decode(source string) ([]byte, error) {
    if len(source) == 0 {
        return []byte{}, nil
    }

    var (
        data = []rune(source)
        dest = big.NewInt(0)
    )

    for i := 0; i < len(data); i++ {
        value, ok := this.alphabetMap[data[i]]
        if !ok {
            return nil, errors.New("non Base Character")
        }

        dest.Mul(dest, this.base)
        if value > 0 {
            dest.Add(dest, big.NewInt(int64(value)))
        }
    }

    k := 0
    for ; data[k] == this.alphabet[0] && k < len(data)-1; k++ {
    }

    buf := dest.Bytes()
    res := make([]byte, k, k+len(buf))

    return append(res, buf...), nil
}
