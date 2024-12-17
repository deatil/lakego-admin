package loki97

import (
    "sync"
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    BlockSize = 16
)

var (
    once sync.Once

    S1 [S1_SIZE]byte
    S2 [S2_SIZE]byte

    P [PERMUTATION_SIZE]ULONG64
)

func initAll() {
    S1 = generationS1Box()
    S2 = generationS2Box()

    P = permutationGeneration()
}

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/loki97: invalid key size " + strconv.Itoa(int(k))
}

type loki97Cipher struct {
    key []ULONG64
}

// NewCipher creates and returns a new cipher.Block.
// data bytes use BigEndian, if is LittleEndian
// please change BigEndian bytes
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    once.Do(initAll)

    newKey := makeKey(key)

    c := new(loki97Cipher)
    c.key = newKey[:]

    return c, nil
}

func (this *loki97Cipher) BlockSize() int {
    return BlockSize
}

func (this *loki97Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/loki97: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/loki97: invalid buffer overlap")
    }

    encBlock := blockEncrypt(src, this.key)
    copy(dst, encBlock)
}

func (this *loki97Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/loki97: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/loki97: invalid buffer overlap")
    }

    decBlock := blockDecrypt(src, this.key);
    copy(dst, decBlock)
}
