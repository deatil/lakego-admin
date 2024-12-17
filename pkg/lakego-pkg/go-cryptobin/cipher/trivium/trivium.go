package trivium

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/trivium: invalid key size " + strconv.Itoa(int(k))
}

type IVSizeError int

func (k IVSizeError) Error() string {
    return "go-cryptobin/trivium: invalid iv size " + strconv.Itoa(int(k))
}

type triviumCipher struct {
    key [36]uint8
}

// NewCipher creates and returns a new cipher.Stream.
func NewCipher(key []byte, iv []byte) (cipher.Stream, error) {
    keyLen := len(key)
    if keyLen != 10 {
        return nil, KeySizeError(keyLen)
    }

    ivLen := len(iv)
    if ivLen != 10 {
        return nil, IVSizeError(keyLen)
    }

    c := new(triviumCipher)
    c.expandKey(key, iv)

    return c, nil
}

func (this *triviumCipher) XORKeyStream(dst []byte, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/trivium: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/trivium: invalid buffer overlap")
    }

    var i int
    var ks uint8

    //Encryption loop
    for i = 0; i < len(src); i++ {
        //Generate one byte of key stream
        ks = this.triviumGenerateByte()

        //XOR the input data with the keystream
        dst[i] = src[i] ^ ks;
    }
}

func (this *triviumCipher) expandKey(key []byte, iv []byte) {
    var i uint

    //Clear the 288-bit internal state
    this.key = [36]uint8{}

    //Let (s1, s2, ..., s93) = (K1, ..., K80, 0, ..., 0)
    for i = 0; i < 10; i++ {
        this.key[i] = reverseInt8(key[9 - i])
    }

    //Load the 80-bit initialization vector
    for i = 0; i < 10; i++ {
        this.key[12 + i] = reverseInt8(iv[9 - i])
    }

    //Let (s94, s95, ..., s177) = (IV1, ..., IV80, 0, ..., 0)
    for i = 11; i < 22; i++ {
        this.key[i] = (this.key[i + 1] << 5) | (this.key[i] >> 3)
    }

    //Let (s178, s279, ..., s288) = (0, ..., 0, 1, 1, 1)
    TRIVIUM_SET_BIT(this.key[:], 286, 1)
    TRIVIUM_SET_BIT(this.key[:], 287, 1)
    TRIVIUM_SET_BIT(this.key[:], 288, 1)

    //The state is rotated over 4 full cycles, without generating key stream bit
    for i = 0; i < (4 * 288); i++ {
        this.triviumGenerateBit()
    }

}

func (this *triviumCipher) triviumGenerateBit() uint8 {
   var i int

   var t1 uint8
   var t2 uint8
   var t3 uint8
   var z uint8

   //Let t1 = s66 + s93
   t1 = TRIVIUM_GET_BIT(this.key[:], 66)
   t1 ^= TRIVIUM_GET_BIT(this.key[:], 93)

   //Let t2 = s162 + s177
   t2 = TRIVIUM_GET_BIT(this.key[:], 162)
   t2 ^= TRIVIUM_GET_BIT(this.key[:], 177)

   //Let t3 = s243 + s288
   t3 = TRIVIUM_GET_BIT(this.key[:], 243)
   t3 ^= TRIVIUM_GET_BIT(this.key[:], 288)

   //Generate a key stream bit z
   z = t1 ^ t2 ^ t3

   //Let t1 = t1 + s91.s92 + s171
   t1 ^= TRIVIUM_GET_BIT(this.key[:], 91) & TRIVIUM_GET_BIT(this.key[:], 92)
   t1 ^= TRIVIUM_GET_BIT(this.key[:], 171)

   //Let t2 = t2 + s175.s176 + s264
   t2 ^= TRIVIUM_GET_BIT(this.key[:], 175) & TRIVIUM_GET_BIT(this.key[:], 176)
   t2 ^= TRIVIUM_GET_BIT(this.key[:], 264)

   //Let t3 = t3 + s286.s287 + s69
   t3 ^= TRIVIUM_GET_BIT(this.key[:], 286) & TRIVIUM_GET_BIT(this.key[:], 287)
   t3 ^= TRIVIUM_GET_BIT(this.key[:], 69)

   //Rotate the internal state
   for i = 35; i > 0; i-- {
      this.key[i] = (this.key[i] << 1) | (this.key[i - 1] >> 7)
   }

   this.key[0] = this.key[0] << 1

   //Let s1 = t3
   TRIVIUM_SET_BIT(this.key[:], 1, t3)
   //Let s94 = t1
   TRIVIUM_SET_BIT(this.key[:], 94, t1)
   //Let s178 = t2
   TRIVIUM_SET_BIT(this.key[:], 178, t2)

   //Return one bit of key stream
   return z;
}

func (this *triviumCipher) triviumGenerateByte() uint8 {
   var i int
   var ks uint8

   //Initialize value
   ks = 0

   //Generate 8 bits of key stream
   for i = 0; i < 8; i++ {
      ks |= this.triviumGenerateBit() << i;
   }

   //Return one byte of key stream
   return ks;
}
