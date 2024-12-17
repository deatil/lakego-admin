package rijndael

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    BlockSize128 = 16
    BlockSize160 = 20
    BlockSize192 = 24
    BlockSize224 = 28
    BlockSize256 = 32
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/rijndael: invalid key size " + strconv.Itoa(int(k))
}

type BlockSizeError int

func (k BlockSizeError) Error() string {
    return "go-cryptobin/rijndael: invalid block size " + strconv.Itoa(int(k))
}

type rijndaelCipher struct {
    Nk, Nb, Nr int32
    fi, ri [24]byte
    fkey [120]uint32
    rkey [120]uint32
    blockSize int
}

// NewCipher returns a new rijndael cipher with the given key and effective key length t1
func NewCipher(key []byte, blockSize int) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 20, 24, 28, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    switch blockSize {
        case 16, 20, 24, 28, 32:
            break
        default:
            return nil, BlockSizeError(k)
    }

    c := new(rijndaelCipher)
    c.blockSize = blockSize
    c.expandKey(key, int32(blockSize) / 4, int32(k))

    return c, nil
}

// NewCipher128 returns a new rijndael cipher with the given key and effective key length t1
func NewCipher128(key []byte) (cipher.Block, error) {
    return NewCipher(key, BlockSize128)
}

// NewCipher160 returns a new rijndael cipher with the given key and effective key length t1
func NewCipher160(key []byte) (cipher.Block, error) {
    return NewCipher(key, BlockSize160)
}

// NewCipher192 returns a new rijndael cipher with the given key and effective key length t1
func NewCipher192(key []byte) (cipher.Block, error) {
    return NewCipher(key, BlockSize192)
}

// NewCipher224 returns a new rijndael cipher with the given key and effective key length t1
func NewCipher224(key []byte) (cipher.Block, error) {
    return NewCipher(key, BlockSize224)
}

// NewCipher256 returns a new rijndael cipher with the given key and effective key length t1
func NewCipher256(key []byte) (cipher.Block, error) {
    return NewCipher(key, BlockSize256)
}

func (this *rijndaelCipher) BlockSize() int {
    return this.blockSize
}

func (this *rijndaelCipher) Encrypt(dst, src []byte) {
    if len(src) < this.blockSize {
        panic("go-cryptobin/rijndael: input not full block")
    }

    if len(dst) < this.blockSize {
        panic("go-cryptobin/rijndael: output not full block")
    }

    if alias.InexactOverlap(dst[:this.blockSize], src[:this.blockSize]) {
        panic("go-cryptobin/rijndael: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *rijndaelCipher) Decrypt(dst, src []byte) {
    if len(src) < this.blockSize {
        panic("go-cryptobin/rijndael: input not full block")
    }

    if len(dst) < this.blockSize {
        panic("go-cryptobin/rijndael: output not full block")
    }

    if alias.InexactOverlap(dst[:this.blockSize], src[:this.blockSize]) {
        panic("go-cryptobin/rijndael: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *rijndaelCipher) encrypt(dst, src []byte) {
    var i, j, k, m int32
    var a, b [8]uint32
    var x, y []uint32

    for i, j = 0, 0; i < this.Nb; i, j = i+1, j+4 {
        a[i] = pack(src[j:])
        a[i] ^= this.fkey[i]
    }

    k = this.Nb
    x = a[:]
    y = b[:]

    for i = 1; i < this.Nr; i++ {

        for m, j = 0, 0; j < this.Nb; j, m = j+1, m+3 {
            y[j] = this.fkey[k] ^ ftable[byte(x[j])] ^
                rotl8(ftable[byte(x[this.fi[m]] >> 8)]) ^
                rotl16(ftable[byte(x[this.fi[m + 1]] >> 16)]) ^
                rotl24(ftable[byte(x[this.fi[m + 2]] >> 24)])
            k++
        }

        x, y = y, x
    }

    for m, j = 0, 0; j < this.Nb; j, m = j+1, m+3 {
        y[j] = this.fkey[k] ^ uint32(fbsub[byte(x[j])]) ^
            rotl8(uint32(fbsub[byte(x[this.fi[m]] >> 8)])) ^
            rotl16(uint32(fbsub[byte(x[this.fi[m + 1]] >> 16)])) ^
            rotl24(uint32(fbsub[byte(x[this.fi[m + 2]] >> 24)]))
        k++
    }

    for i, j = 0, 0; i < this.Nb; i, j = i+1, j+4 {
        unpack(y[i], dst[j:])
    }
}

func (this *rijndaelCipher) decrypt(dst, src []byte) {
    var i, j, k, m int32
    var a, b [8]uint32
    var x, y []uint32

    for i, j = 0, 0; i < this.Nb; i, j = i+1, j+4 {
        a[i] = pack(src[j:])
        a[i] ^= this.rkey[i]
    }

    k = this.Nb
    x = a[:]
    y = b[:]

    for i = 1; i < this.Nr; i++ {
        for m, j = 0, 0; j < this.Nb; j, m = j+1, m+3 {
            y[j] = this.rkey[k] ^ rtable[byte(x[j])] ^
                rotl8(rtable[byte(x[this.ri[m]] >> 8)]) ^
                rotl16(rtable[byte(x[this.ri[m + 1]] >> 16)]) ^
                rotl24(rtable[byte(x[this.ri[m + 2]] >> 24)])
            k++
        }

        x, y = y, x
    }

    for m, j = 0, 0; j < this.Nb; j, m = j+1, m+3 {
        y[j] = this.rkey[k] ^ uint32(rbsub[byte(x[j])]) ^
            rotl8(uint32(rbsub[byte(x[this.ri[m]] >> 8)])) ^
            rotl16(uint32(rbsub[byte(x[this.ri[m + 1]] >> 16)])) ^
            rotl24(uint32(rbsub[byte(x[this.ri[m + 2]] >> 24)]))
        k++
    }

    for i, j = 0, 0; i < this.Nb; i, j = i+1, j+4 {
        unpack(y[i], dst[j:])
    }
}

func (this *rijndaelCipher) expandKey(key []byte, nb, nk int32) {
    /* blocksize=32*nb bits. Key=32*nk bits */
    /* currently nb,bk = 4, 6 or 8          */
    /* key comes as 4*rinst->Nk bytes              */
    /* Key Scheduler. Create expanded encryption key */
    var i, j, k, m, N int32
    var C1, C2, C3 int32
    var CipherKey [8]uint32

    nk /= 4
    if nk < 4 {
        nk = 4
    }

    this.Nb = nb /* block size */
    this.Nk = nk

    /* rinst->Nr is number of rounds */
    if this.Nb >= this.Nk {
        this.Nr = 6 + this.Nb
    } else {
        this.Nr = 6 + this.Nk
    }

    C1 = 1
    if this.Nb < 8 {
        C2 = 2
        C3 = 3
    } else {
        C2 = 3
        C3 = 4
    }

    /* pre-calculate forward and reverse increments */
    for m, j = 0, 0; j < nb; j, m = j + 1, m + 3 {
        this.fi[m    ] = byte((j + C1) % nb)
        this.fi[m + 1] = byte((j + C2) % nb)
        this.fi[m + 2] = byte((j + C3) % nb)

        this.ri[m    ] = byte((nb + j - C1) % nb)
        this.ri[m + 1] = byte((nb + j - C2) % nb)
        this.ri[m + 2] = byte((nb + j - C3) % nb)
    }

    N = this.Nb * (this.Nr + 1)

    for i, j = 0, 0; i < this.Nk; i, j = i + 1, j + 4 {
        CipherKey[i] = pack(key[j:])
    }

    for i = 0; i < this.Nk; i++ {
        this.fkey[i] = CipherKey[i]
    }

    for j, k = this.Nk, 0; j < N; j, k = j + this.Nk, k + 1 {
        this.fkey[j] = this.fkey[j - this.Nk] ^ subByte(rotl24(this.fkey[j - 1])) ^ rco[k]
        if this.Nk <= 6 {
            for i = 1; i < this.Nk && (i + j) < N; i++ {
                this.fkey[i + j] = this.fkey[i + j - this.Nk] ^ this.fkey[i + j - 1]
            }
        } else {
            for i = 1; i < 4 && (i + j) < N; i++ {
                this.fkey[i + j] = this.fkey[i + j - this.Nk] ^ this.fkey[i + j - 1]
            }

            if (j + 4) < N {
                this.fkey[j + 4] = this.fkey[j + 4 - this.Nk] ^ subByte(this.fkey[j + 3])
            }

            for i = 5; i < this.Nk && (i + j) < N; i++ {
                this.fkey[i + j] = this.fkey[i + j - this.Nk] ^ this.fkey[i + j - 1]
            }
        }

    }

    /* now for the expanded decrypt key in reverse order */
    for j = 0; j < this.Nb; j++ {
        this.rkey[j + N - this.Nb] = this.fkey[j]
    }

    for i = this.Nb; i < N - this.Nb; i += this.Nb {
        k = N - this.Nb - i
        for j = 0; j < this.Nb; j++ {
            this.rkey[k + j] = invMixCol(this.fkey[i + j])
        }
    }

    for j = N - this.Nb; j < N; j++ {
        this.rkey[j - N + this.Nb] = this.fkey[j]
    }
}
