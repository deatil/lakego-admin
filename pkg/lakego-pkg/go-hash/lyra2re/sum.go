package lyra2re

import (
    "golang.org/x/crypto/sha3"

    "github.com/deatil/go-hash/skein"
    "github.com/deatil/go-hash/groestl"
    "github.com/deatil/go-hash/blake256"
)

// Sum returns the result of Lyra2re hash.
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
    resultKeccak := keccak.Sum(nil)

    lyra2Result := make([]byte, 32)
    Lyra2(lyra2Result, resultKeccak, resultKeccak, 1, 8, 8)

    skeinResult := skein.Sum256(lyra2Result, nil)

    groestlResult := groestl.Sum256(skeinResult[:])

    return groestlResult[:], nil
}
