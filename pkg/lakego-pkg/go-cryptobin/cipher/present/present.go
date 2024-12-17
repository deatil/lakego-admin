package present

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/present: invalid key size " + strconv.Itoa(int(k))
}

type presentCipher struct {
    key [32]uint64
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    keyLen := len(key)

    // Check key length
    if keyLen != 10 && keyLen != 16 {
        return nil, KeySizeError(keyLen)
    }

    c := new(presentCipher)
    c.expandKey(key)

    return c, nil
}

func (this *presentCipher) BlockSize() int {
    return BlockSize
}

func (this *presentCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/present: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/present: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/present: invalid buffer overlap")
    }

    this.encryptBlock(dst, src)
}

func (this *presentCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/present: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/present: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/present: invalid buffer overlap")
    }

    this.decryptBlock(dst, src)
}

func (this *presentCipher) expandKey(key []byte) {
   var i uint

   var t uint64
   var kl uint64
   var kh uint64

   keyLen := len(key)

   //PRESENT can take keys of either 80 or 128 bits
   if keyLen == 10 {
      //Copy the 80-bit key
      kh = bytesToUint64(key)
      kl = bytesToUint64(key[2:])

      //Save the 64 leftmost bits of K
      this.key[0] = (kh << 48) | (kl >> 16)

      //Generate round keys
      for i = 1; i <= 31; i++ {
         //The key register is rotated by 61 bit positions to the left
         t = kh & 0xFFFF
         kh = (kl >> 3) & 0xFFFF
         kl = (kl << 61) | (t << 45) | (kl >> 19)

         //The left-most four bits are passed through the S-box
         t = uint64(sbox[(kh >> 12) & 0x0F])
         kh = (kh & 0x0FFF) | (t << 12)

         //The round counter value i is XOR-ed with bits 19, 18, 17, 16, 15 of K
         kl ^= uint64(i) << 15

         //Save the 64 leftmost bits of K
         this.key[i] = (kh << 48) | (kl >> 16)
      }
   } else {
      //Copy the 128-bit key
      kh = bytesToUint64(key)
      kl = bytesToUint64(key[8:])

      //Save the 64 leftmost bits of K
      this.key[0] = kh

      //Generate round keys
      for i = 1; i <= 31; i++ {
         //The key register is rotated by 61 bit positions to the left
         t = kh
         kh = (t << 61) | (kl >> 3)
         kl = (kl << 61) | (t >> 3)

         //The left-most eight bits are passed through two S-boxes
         t = uint64(sbox[(kh >> 56) & 0x0F])
         kh = (kh & 0xF0FFFFFFFFFFFFFF) | (t << 56)
         t = uint64(sbox[(kh >> 60) & 0x0F])
         kh = (kh & 0x0FFFFFFFFFFFFFFF) | (t << 60)

         //The round counter value i is XOR-ed with bits 66, 65, 64, 63, 62 of K
         kh ^= uint64(i) >> 2
         kl ^= uint64(i) << 62

         //Save the 64 leftmost bits of K
         this.key[i] = kh
      }
   }

}

func (this *presentCipher) encryptBlock(output []byte, input []byte){
    var i uint

    var s uint64
    var t uint64
    var state uint64

    //Copy the plaintext to the 64-bit state
    state = bytesToUint64(input)

    //Initial round key addition
    state ^= this.key[0];

    //The encryption consists of 31 rounds
    for i = 1; i <= 31; i++ {
        //Apply S-box and bit permutation
        s = spbox[state & 0xFF]
        t = spbox[(state >> 8) & 0xFF]
        s |= ROL64(t, 2)
        t = spbox[(state >> 16) & 0xFF]
        s |= ROL64(t, 4)
        t = spbox[(state >> 24) & 0xFF]
        s |= ROL64(t, 6)
        t = spbox[(state >> 32) & 0xFF]
        s |= ROL64(t, 8)
        t = spbox[(state >> 40) & 0xFF]
        s |= ROL64(t, 10)
        t = spbox[(state >> 48) & 0xFF]
        s |= ROL64(t, 12)
        t = spbox[(state >> 56) & 0xFF]
        s |= ROL64(t, 14)

        //Add round key
        state = s ^ this.key[i]
    }

    //The final state is then copied to the output
    stateBytes := uint64ToBytes(state)
    copy(output, stateBytes[:])
}

func (this *presentCipher) decryptBlock(output []byte, input []byte) {
    var i uint

    var s uint64
    var t uint64
    var state uint64

    //Copy the ciphertext to the 64-bit state
    state = bytesToUint64(input)

    //The decryption consists of 31 rounds
    for i = 31; i > 0; i-- {
        //Add round key
        state ^= this.key[i]

        //Apply inverse bit permutation
        s = uint64(ipbox[state & 0xFF])
        t = uint64(ipbox[(state >> 8) & 0xFF])
        s |= ROL64(t, 32)
        t = uint64(ipbox[(state >> 16) & 0xFF])
        s |= ROL64(t, 1)
        t = uint64(ipbox[(state >> 24) & 0xFF])
        s |= ROL64(t, 33)
        t = uint64(ipbox[(state >> 32) & 0xFF])
        s |= ROL64(t, 2)
        t = uint64(ipbox[(state >> 40) & 0xFF])
        s |= ROL64(t, 34)
        t = uint64(ipbox[(state >> 48) & 0xFF])
        s |= ROL64(t, 3)
        t = uint64(ipbox[(state >> 56) & 0xFF])
        s |= ROL64(t, 35)

        //Apply inverse S-box
        state = uint64(isbox[s & 0xFF])
        t = uint64(isbox[(s >> 8) & 0xFF])
        state |= ROL64(t, 8)
        t = uint64(isbox[(s >> 16) & 0xFF])
        state |= ROL64(t, 16);
        t = uint64(isbox[(s >> 24) & 0xFF])
        state |= ROL64(t, 24)
        t = uint64(isbox[(s >> 32) & 0xFF])
        state |= ROL64(t, 32)
        t = uint64(isbox[(s >> 40) & 0xFF])
        state |= ROL64(t, 40)
        t = uint64(isbox[(s >> 48) & 0xFF])
        state |= ROL64(t, 48)
        t = uint64(isbox[(s >> 56) & 0xFF])
        state |= ROL64(t, 56)
    }

    //Final round key addition
    state ^= this.key[0]

    //The final state is then copied to the output
    stateBytes := uint64ToBytes(state)
    copy(output, stateBytes[:])
}
