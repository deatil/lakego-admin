package pgp_s2k

import (
    "time"
    "hash"
    "bytes"

    "github.com/deatil/go-cryptobin/tool/math"
)

/**
* OpenPGP's S2K
*
* See RFC 4880 sections 3.7.1.1, 3.7.1.2, and 3.7.1.3
* If the salt is empty and iterations == 1, "simple" S2K is used
* If the salt is non-empty and iterations == 1, "salted" S2K is used
* If the salt is non-empty and iterations > 1, "iterated" S2K is used
*
* Due to complexities of the PGP S2K algorithm, time-based derivation
* is not supported. So if iterations == 0 and msec.count() > 0, an
* exception is thrown. In the future this may be supported, in which
* case "iterated" S2K will be used and the number of iterations
* performed is returned.
*/
func Key(h func() hash.Hash, password, salt []byte, iterations, keylen int) []byte {
    if (iterations > 1 && len(salt) == 0) {
        panic("go-cryptobin/pgp_s2k: OpenPGP S2K requires a salt in iterated mode")
    }

    newHash := h()

    inputBuf := make([]byte, len(salt) + len(password))
    copy(inputBuf[:], salt)
    copy(inputBuf[len(salt):], password)

    var hashBuf []byte
    var outputBuf []byte

    var pass int = 0
    var generated int = 0

    for generated < keylen {
        outputThisPass := math.Min(newHash.Size(), keylen - generated)

        newHash.Reset()

        // Preload some number of zero bytes (empty first iteration)
        zeroPadding := bytes.Repeat([]byte{0}, pass)
        newHash.Write(zeroPadding)

        // The input is always fully processed even if iterations is very small
        if len(inputBuf) > 0 {
            left := math.Max(iterations, len(inputBuf))
            for left > 0 {
                input2Take := math.Min(left, len(inputBuf))
                newHash.Write(inputBuf[:input2Take])
                left -= input2Take
            }
        }

        hashBuf = newHash.Sum(nil)

        outputBuf = append(outputBuf, hashBuf[:outputThisPass]...)

        generated += outputThisPass
        pass++
    }

    return outputBuf
}

func KeyWithTune(h func() hash.Hash, password, salt []byte, iterations, keylen int, msec time.Duration) []byte {
    if iterations == 0 {
        iterations = tune(h(), keylen, msec, 0, 10 * time.Millisecond)
    }

    return Key(h, password, salt, iterations, keylen)
}
