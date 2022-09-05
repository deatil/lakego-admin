package pbkdf

import (
    "hash"
    "bytes"
    "math/big"
)

var (
    one = big.NewInt(1)
)

func Key(h func() hash.Hash, u, v int, salt, password []byte, r int, ID byte, size int) (key []byte) {
    var D []byte
    for i := 0; i < v; i++ {
        D = append(D, ID)
    }

    S := fillWithRepeats(salt, v)
    P := fillWithRepeats(password, v)
    I := append(S, P...)

    c := (size + u - 1) / u

    A := make([]byte, c*u)
    var IjBuf []byte
    for i := 0; i < c; i++ {
        Ai := hashFunc(h, append(D, I...))
        for j := 1; j < r; j++ {
            Ai = hashFunc(h, Ai)
        }
        copy(A[i*u:], Ai[:])

        if i < c-1 {
            var B []byte
            for len(B) < v {
                B = append(B, Ai[:]...)
            }
            B = B[:v]

            {
                Bbi := new(big.Int).SetBytes(B)
                Ij := new(big.Int)

                for j := 0; j < len(I)/v; j++ {
                    Ij.SetBytes(I[j*v : (j+1)*v])
                    Ij.Add(Ij, Bbi)
                    Ij.Add(Ij, one)
                    Ijb := Ij.Bytes()

                    if len(Ijb) > v {
                        Ijb = Ijb[len(Ijb)-v:]
                    }
                    if len(Ijb) < v {
                        if IjBuf == nil {
                            IjBuf = make([]byte, v)
                        }
                        bytesShort := v - len(Ijb)
                        for i := 0; i < bytesShort; i++ {
                            IjBuf[i] = 0
                        }
                        copy(IjBuf[bytesShort:], Ijb)
                        Ijb = IjBuf
                    }
                    copy(I[j*v:(j+1)*v], Ijb)
                }
            }
        }
    }

    return A[:size]
}

// 单个加密
func hashFunc(h func() hash.Hash, key []byte) []byte {
    fn := h()
    fn.Write(key)
    data := fn.Sum(nil)

    return data
}

func fillWithRepeats(pattern []byte, v int) []byte {
    if len(pattern) == 0 {
        return nil
    }
    outputLen := v * ((len(pattern) + v - 1) / v)
    return bytes.Repeat(pattern, (outputLen+len(pattern)-1)/len(pattern))[:outputLen]
}
