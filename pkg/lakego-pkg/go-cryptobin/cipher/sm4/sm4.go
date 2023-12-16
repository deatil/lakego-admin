package sm4

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

const KeySchedule = 32

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/sm4: invalid key size " + strconv.Itoa(int(k))
}

type sm4Cipher struct {
    rk [KeySchedule]uint32
}

// NewCipher creates and returns a new cipher.Block.
// key is 16 bytes, so 32 bytes is used half bytes.
// so the cipher use 16 bytes key.
// key bytes and src bytes is BigEndian type.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(sm4Cipher)
    c.setKey(key)

    return c, nil
}

func (this *sm4Cipher) BlockSize() int {
    return BlockSize
}

func (this *sm4Cipher) Encrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/sm4: output not full block")
    }

    bs := len(src)

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("cryptobin/sm4: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *sm4Cipher) Decrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/sm4: output not full block")
    }

    bs := len(src)

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("cryptobin/sm4: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *sm4Cipher) encrypt(dst, src []byte) {
    var B0 uint32 = bytesToUint32(src[0:])
    var B1 uint32 = bytesToUint32(src[4:])
    var B2 uint32 = bytesToUint32(src[8:])
    var B3 uint32 = bytesToUint32(src[12:])

    /*
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     */
    this.RNDS(&B0, &B1, &B2, &B3,  0,  1,  2,  3, T_slow)
    this.RNDS(&B0, &B1, &B2, &B3,  4,  5,  6,  7, T)
    this.RNDS(&B0, &B1, &B2, &B3,  8,  9, 10, 11, T)
    this.RNDS(&B0, &B1, &B2, &B3, 12, 13, 14, 15, T)
    this.RNDS(&B0, &B1, &B2, &B3, 16, 17, 18, 19, T)
    this.RNDS(&B0, &B1, &B2, &B3, 20, 21, 22, 23, T)
    this.RNDS(&B0, &B1, &B2, &B3, 24, 25, 26, 27, T)
    this.RNDS(&B0, &B1, &B2, &B3, 28, 29, 30, 31, T_slow)

    B3Bytes := uint32ToBytes(B3)
    B2Bytes := uint32ToBytes(B2)
    B1Bytes := uint32ToBytes(B1)
    B0Bytes := uint32ToBytes(B0)

    copy(dst, B3Bytes[:])
    copy(dst[4:], B2Bytes[:])
    copy(dst[8:], B1Bytes[:])
    copy(dst[12:], B0Bytes[:])
}

func (this *sm4Cipher) decrypt(dst, src []byte) {
    var B0 uint32 = bytesToUint32(src[0:])
    var B1 uint32 = bytesToUint32(src[4:])
    var B2 uint32 = bytesToUint32(src[8:])
    var B3 uint32 = bytesToUint32(src[12:])

    this.RNDS(&B0, &B1, &B2, &B3, 31, 30, 29, 28, T_slow)
    this.RNDS(&B0, &B1, &B2, &B3, 27, 26, 25, 24, T)
    this.RNDS(&B0, &B1, &B2, &B3, 23, 22, 21, 20, T)
    this.RNDS(&B0, &B1, &B2, &B3, 19, 18, 17, 16, T)
    this.RNDS(&B0, &B1, &B2, &B3, 15, 14, 13, 12, T)
    this.RNDS(&B0, &B1, &B2, &B3, 11, 10,  9,  8, T)
    this.RNDS(&B0, &B1, &B2, &B3,  7,  6,  5,  4, T)
    this.RNDS(&B0, &B1, &B2, &B3,  3,  2,  1,  0, T_slow)

    B3Bytes := uint32ToBytes(B3)
    B2Bytes := uint32ToBytes(B2)
    B1Bytes := uint32ToBytes(B1)
    B0Bytes := uint32ToBytes(B0)

    copy(dst, B3Bytes[:])
    copy(dst[4:], B2Bytes[:])
    copy(dst[8:], B1Bytes[:])
    copy(dst[12:], B0Bytes[:])
}

func (this *sm4Cipher) RNDS(B0, B1, B2, B3 *uint32, k0, k1, k2, k3 int, F func(uint32) uint32) {
    (*B0) ^= F((*B1) ^ (*B2) ^ (*B3) ^ this.rk[k0])
    (*B1) ^= F((*B0) ^ (*B2) ^ (*B3) ^ this.rk[k1])
    (*B2) ^= F((*B0) ^ (*B1) ^ (*B3) ^ this.rk[k2])
    (*B3) ^= F((*B0) ^ (*B1) ^ (*B2) ^ this.rk[k3])
}

func (this *sm4Cipher) setKey(key []byte) {
    /*
     * Family Key
     */
    var FK = [4]uint32{
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
    };

    /*
     * Constant Key
     */
    var CK = [32]uint32{
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
    };

    var K [4]uint32
    var i int32

    K[0] = bytesToUint32(key[0:]) ^ FK[0]
    K[1] = bytesToUint32(key[4:]) ^ FK[1]
    K[2] = bytesToUint32(key[8:]) ^ FK[2]
    K[3] = bytesToUint32(key[12:]) ^ FK[3]

    for i = 0; i < KeySchedule; i = i + 4 {
        K[0] ^= key_sub(K[1] ^ K[2] ^ K[3] ^ CK[i])
        K[1] ^= key_sub(K[2] ^ K[3] ^ K[0] ^ CK[i + 1])
        K[2] ^= key_sub(K[3] ^ K[0] ^ K[1] ^ CK[i + 2])
        K[3] ^= key_sub(K[0] ^ K[1] ^ K[2] ^ CK[i + 3])

        this.rk[i    ] = K[0]
        this.rk[i + 1] = K[1]
        this.rk[i + 2] = K[2]
        this.rk[i + 3] = K[3]
    }
}
