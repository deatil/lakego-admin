package pbkdf

import (
    "hash"
    "bytes"
    "math/big"
)

// implementation of https://tools.ietf.org/html/rfc7292#appendix-B.2 , RFC text verbatim in comments

//    Let H be a hash function built around a compression function f:

//       Z_2^u x Z_2^v -> Z_2^u

//    (that is, H has a chaining variable and output of length u bits, and
//    the message input to the compression function of H is v bits).  The
//    values for u and v are as follows:

//            HASH FUNCTION     VALUE u        VALUE v
//              MD2, MD5          128            512
//                SHA-1           160            512
//               SHA-224          224            512
//               SHA-256          256            512
//               SHA-384          384            1024
//               SHA-512          512            1024
//             SHA-512/224        224            1024
//             SHA-512/256        256            1024

//    Furthermore, let r be the iteration count.

//    We assume here that u and v are both multiples of 8, as are the
//    lengths of the password and salt strings (which we denote by p and s,
//    respectively) and the number n of pseudorandom bits required.  In
//    addition, u and v are of course non-zero.

//    For information on security considerations for MD5 [19], see [25] and
//    [1], and on those for MD2, see [18].

//    The following procedure can be used to produce pseudorandom bits for
//    a particular "purpose" that is identified by a byte called "ID".
//    This standard specifies 3 different values for the ID byte:

//    1.  If ID=1, then the pseudorandom bits being produced are to be used
//        as key material for performing encryption or decryption.

//    2.  If ID=2, then the pseudorandom bits being produced are to be used
//        as an IV (Initial Value) for encryption or decryption.

//    3.  If ID=3, then the pseudorandom bits being produced are to be used
//        as an integrity key for MACing.

//    1.  Construct a string, D (the "diversifier"), by concatenating v/8
//        copies of ID.

var one = big.NewInt(1)

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
