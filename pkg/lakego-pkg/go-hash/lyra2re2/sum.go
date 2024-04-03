package lyra2re2

import (
    "golang.org/x/crypto/sha3"

    "github.com/deatil/go-hash/bmw"
    "github.com/deatil/go-hash/skein"
    "github.com/deatil/go-hash/blake256"
    "github.com/deatil/go-hash/cubehash256"
)

// Sum returns the result of Lyra2re2 hash.
func Sum(data []byte) ([]byte, error) {
    blake := blake256.New()
    if _, err := blake.Write(data); err != nil {
        return nil, err
    }

    resultBlake := blake.Sum(nil)

    keccak := sha3.NewLegacyKeccak256()
    if _, err := keccak.Write(resultBlake); err != nil {
        return nil, err
    }
    resultkeccak := keccak.Sum(nil)

    resultcube := cubehash256.Sum(resultkeccak)

    lyra2result := make([]byte, 32)
    Lyra2(lyra2result, resultcube[:], resultcube[:], 1, 4, 4)

    var skeinresult [32]byte
    skein.Sum256(&skeinresult, lyra2result, nil)

    resultcube2 := cubehash256.Sum(skeinresult[:])
    resultbmw := bmw.Sum(resultcube2[:])

    return resultbmw[:], nil
}
