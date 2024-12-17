package saferplus

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

const (
    TAB_LEN = 256
    SAFER_BLOCK_LEN = 8
    SAFER_MAX_NOF_ROUNDS = 13
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/saferplus: invalid key size " + strconv.Itoa(int(k))
}

type saferplusCipher struct {
    local_key [217]uint8
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 8, 16:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(saferplusCipher)
    c.expandKey(key)

    return c, nil
}

func (this *saferplusCipher) BlockSize() int {
    return BlockSize
}

func (this *saferplusCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/saferplus: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/saferplus: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/saferplus: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *saferplusCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/saferplus: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/saferplus: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/saferplus: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *saferplusCipher) encrypt(dst, src []byte) {
    var t uint8
    var rnd uint32
    var key = this.local_key

    var ciphertext [8]uint8

    for i, text := range src {
        ciphertext[i] = uint8(text)
    }

    rnd = uint32(key[0])

    if SAFER_MAX_NOF_ROUNDS < rnd {
        rnd = SAFER_MAX_NOF_ROUNDS;
    }

    var xi uint32 = 0

    for i := rnd; i > 0; i--  {
        xi++
        ciphertext[0] ^= key[xi]
        xi++
        ciphertext[1] += key[xi]
        xi++
        ciphertext[2] += key[xi]
        xi++
        ciphertext[3] ^= key[xi]
        xi++
        ciphertext[4] ^= key[xi]
        xi++
        ciphertext[5] += key[xi]
        xi++
        ciphertext[6] += key[xi]
        xi++
        ciphertext[7] ^= key[xi]

        xi++
        ciphertext[0] = exp_tab[ciphertext[0] & 0xFF] + key[xi]
        xi++
        ciphertext[1] = log_tab[ciphertext[1] & 0xFF] ^ key[xi]
        xi++
        ciphertext[2] = log_tab[ciphertext[2] & 0xFF] ^ key[xi]
        xi++
        ciphertext[3] = exp_tab[ciphertext[3] & 0xFF] + key[xi]
        xi++
        ciphertext[4] = exp_tab[ciphertext[4] & 0xFF] + key[xi]
        xi++
        ciphertext[5] = log_tab[ciphertext[5] & 0xFF] ^ key[xi]
        xi++
        ciphertext[6] = log_tab[ciphertext[6] & 0xFF] ^ key[xi]
        xi++
        ciphertext[7] = exp_tab[ciphertext[7] & 0xFF] + key[xi]

        pht(&ciphertext[0], &ciphertext[1])
        pht(&ciphertext[2], &ciphertext[3])
        pht(&ciphertext[4], &ciphertext[5])
        pht(&ciphertext[6], &ciphertext[7])

        pht(&ciphertext[0], &ciphertext[2])
        pht(&ciphertext[4], &ciphertext[6])
        pht(&ciphertext[1], &ciphertext[3])
        pht(&ciphertext[5], &ciphertext[7])
        pht(&ciphertext[0], &ciphertext[4])
        pht(&ciphertext[1], &ciphertext[5])
        pht(&ciphertext[2], &ciphertext[6])
        pht(&ciphertext[3], &ciphertext[7])

        t = ciphertext[1]
        ciphertext[1] = ciphertext[4]
        ciphertext[4] = ciphertext[2]
        ciphertext[2] = t

        t = ciphertext[3]
        ciphertext[3] = ciphertext[5]
        ciphertext[5] = ciphertext[6]
        ciphertext[6] = t
    }

    xi++
    ciphertext[0] ^= key[xi]
    xi++
    ciphertext[1] += key[xi]
    xi++
    ciphertext[2] += key[xi]
    xi++
    ciphertext[3] ^= key[xi]
    xi++
    ciphertext[4] ^= key[xi]
    xi++
    ciphertext[5] += key[xi]
    xi++
    ciphertext[6] += key[xi]
    xi++
    ciphertext[7] ^= key[xi]

    for iii, kkk := range ciphertext {
        dst[iii] = byte(kkk)
    }
}

func (this *saferplusCipher) decrypt(dst, src []byte) {
    var t uint8
    var rnd uint32
    var key = this.local_key

    var plaintext [8]uint8

    for i, text := range src {
        plaintext[i] = uint8(text)
    }

    rnd = uint32(key[0])

    if SAFER_MAX_NOF_ROUNDS < rnd {
        rnd = SAFER_MAX_NOF_ROUNDS
    }

    var xi uint32 = SAFER_BLOCK_LEN * (1 + 2 * rnd)

    plaintext[7] ^= key[xi]
    xi--
    plaintext[6] -= key[xi]
    xi--
    plaintext[5] -= key[xi]
    xi--
    plaintext[4] ^= key[xi]
    xi--
    plaintext[3] ^= key[xi]
    xi--
    plaintext[2] -= key[xi]
    xi--
    plaintext[1] -= key[xi]
    xi--
    plaintext[0] ^= key[xi]

    for i := rnd; i > 0; i--  {
        t = plaintext[4];
        plaintext[4] = plaintext[1];
        plaintext[1] = plaintext[2];
        plaintext[2] = t;

        t = plaintext[5];
        plaintext[5] = plaintext[3];
        plaintext[3] = plaintext[6];
        plaintext[6] = t;

        ipht(&plaintext[0], &plaintext[4]);
        ipht(&plaintext[1], &plaintext[5]);
        ipht(&plaintext[2], &plaintext[6]);
        ipht(&plaintext[3], &plaintext[7]);

        ipht(&plaintext[0], &plaintext[2]);
        ipht(&plaintext[4], &plaintext[6]);
        ipht(&plaintext[1], &plaintext[3]);
        ipht(&plaintext[5], &plaintext[7]);

        ipht(&plaintext[0], &plaintext[1]);
        ipht(&plaintext[2], &plaintext[3]);
        ipht(&plaintext[4], &plaintext[5]);
        ipht(&plaintext[6], &plaintext[7]);

        xi--
        plaintext[7] -= key[xi]
        xi--
        plaintext[6] ^= key[xi]
        xi--
        plaintext[5] ^= key[xi]
        xi--
        plaintext[4] -= key[xi]
        xi--
        plaintext[3] -= key[xi]
        xi--
        plaintext[2] ^= key[xi]
        xi--
        plaintext[1] ^= key[xi]
        xi--
        plaintext[0] -= key[xi]

        xi--
        plaintext[7] = log_tab[plaintext[7] & 0xFF] ^ key[xi]
        xi--
        plaintext[6] = exp_tab[plaintext[6] & 0xFF] - key[xi]
        xi--
        plaintext[5] = exp_tab[plaintext[5] & 0xFF] - key[xi]
        xi--
        plaintext[4] = log_tab[plaintext[4] & 0xFF] ^ key[xi]
        xi--
        plaintext[3] = log_tab[plaintext[3] & 0xFF] ^ key[xi]
        xi--
        plaintext[2] = exp_tab[plaintext[2] & 0xFF] - key[xi]
        xi--
        plaintext[1] = exp_tab[plaintext[1] & 0xFF] - key[xi]
        xi--
        plaintext[0] = log_tab[plaintext[0] & 0xFF] ^ key[xi]
    }

    for iii, kkk := range plaintext {
        dst[iii] = byte(kkk)
    }
}

func (this *saferplusCipher) expandKey(keyData []uint8) {
    var j uint32
    var ka [9]uint8
    var kb [9]uint8
    var key = this.local_key
    var key_buffer [16]uint8

    var xi uint32 = 0

    strengthened := 1
    nofRounds := 8

    for k, v := range keyData {
        key_buffer[k] = v
    }

    if SAFER_MAX_NOF_ROUNDS < nofRounds {
        nofRounds = SAFER_MAX_NOF_ROUNDS;
    }

    key[xi] = uint8(nofRounds)
    xi++

    ka[SAFER_BLOCK_LEN] = 0;
    kb[SAFER_BLOCK_LEN] = 0;

    for j = 0; j < SAFER_BLOCK_LEN; j++ {
        ka[j] = rotl8(key_buffer[j], 5)
        ka[SAFER_BLOCK_LEN] ^= ka[j];

        if len(keyData) > 8 {
            key[xi] = key_buffer[j + 8]
            kb[j] = key[xi]
            xi++
        } else {
            key[xi] = key_buffer[j]
            kb[j] = key[xi]
            xi++
        }

        kb[SAFER_BLOCK_LEN] ^= kb[j]
    }

    var i uint
    for i = 1; i <= uint(nofRounds); i++ {

        var j uint
        for j = 0; j < SAFER_BLOCK_LEN + 1; j++ {
            ka[j] = rotl8(ka[j], 6)
            kb[j] = rotl8(kb[j], 6)
        }

        for j = 0; j < SAFER_BLOCK_LEN; j++ {

            if strengthened == 1 {
                key[xi] =
                    (ka[(j + 2 * i - 1) % (SAFER_BLOCK_LEN + 1)] +
                     exp_tab[exp_tab[18 * i + j + 1]]) &
                    0xFF
                xi++
            } else {
                key[xi] =
                    (ka[j] + exp_tab[exp_tab[18 * i + j + 1]]) &
                    0xFF
                xi++
            }

        }

        for j = 0; j < SAFER_BLOCK_LEN; j++ {

            if strengthened == 1 {
                key[xi] =
                    (kb[(j + 2 * i) % (SAFER_BLOCK_LEN + 1)] +
                     exp_tab[exp_tab[18 * i + j + 10]]) &
                    0xFF
                xi++
            } else {
                key[xi] =
                    (kb[j] + exp_tab[exp_tab[18 * i + j + 10]]) &
                    0xFF
                xi++
            }

        }
    }

    for j = 0; j < SAFER_BLOCK_LEN + 1; j++ {
        ka[j] = 0
        kb[j] = 0
    }

    this.local_key = key
}
