package mars

import (
    "math/bits"
    "encoding/binary"
)

func ROL32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func ROR32(x, n uint32) uint32 {
    return ROL32(x, 32 - n);
}

// S-box S
func S(n uint32) uint32 {
    return sbox[n & 0x1FF]
}

// S-box S0
func S0(n uint32) uint32 {
    return sbox[n & 0xFF]
}

// S-box S1
func S1(n uint32) uint32 {
    return sbox[(n & 0xFF) + 256]
}

func F_MIX(a, b, c, d *uint32) {
   var t uint32

   (*b) ^= S0((*a))
   t = ROR32((*a), 8)

   (*b) += S1(t)
   t = ROR32((*a), 16)

   (*c) += S0(t)
   (*a) = ROR32((*a), 24)

   (*d) ^= S1((*a))
}

// Backwards mixing
func B_MIX(a, b, c, d *uint32) {
   var t uint32

   (*b) ^= S1((*a))
   t = ROL32((*a), 8)

   (*c) -= S0(t)
   t = ROL32((*a), 16)

   (*d) -= S1(t)
   (*a) = ROL32((*a), 24)

   (*d) ^= S0((*a))
}

// Cryptographic core (encryption)
func CORE(a, b, c, d *uint32, k1, k2 uint32) {
   var r uint32
   var l uint32
   var m uint32

   m = (*a) + k1
   (*a) = ROL32((*a), 13)

   r = (*a) * k2
   r = ROL32(r, 5)

   (*c) += ROL32(m, r & 0x1F)

   l = S(m) ^ r
   r = ROL32(r, 5)

   l ^= r
   (*d) ^= r

   (*b) += ROL32(l, r & 0x1F)
}

// Cryptographic core (decryption)
func CORE_INV(a, b, c, d *uint32, k1, k2 uint32) {
   var r uint32
   var l uint32
   var m uint32

   r = (*a) * k2
   (*a) = ROR32((*a), 13)

   m = (*a) + k1
   r = ROL32(r, 5)

   (*c) -= ROL32(m, r & 0x1F)

   l = S(m) ^ r
   r = ROL32(r, 5)

   l ^= r
   (*d) ^= r

   (*b) -= ROL32(l, r & 0x1F)
}

// Mask generation (Brian Gladman and Shai Halevi's technique)
func MASK_GEN(m *uint32, w uint32) {
   (*m) = ^w ^ (w >> 1)
   (*m) &= 0x7FFFFFFF
   (*m) &= ((*m) >> 1) & ((*m) >> 2)
   (*m) &= ((*m) >> 3) & ((*m) >> 6)

   if (*m) != 0 {
      (*m) <<= 1
      (*m) |= ((*m) << 1)
      (*m) |= ((*m) << 2)
      (*m) |= ((*m) << 4)
      (*m) &= 0xFFFFFFFC
   }
}

// Endianness option
const littleEndian bool = true

func bytesToUint32(inp []byte) (blk uint32) {
    if littleEndian {
        blk = binary.LittleEndian.Uint32(inp[0:])
    } else {
        blk = binary.BigEndian.Uint32(inp[0:])
    }

    return
}

func uint32ToBytes(blk uint32) [4]byte {
    var sav [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk)
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk)
    }

    return sav
}

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    if littleEndian {
        blk[0] = binary.LittleEndian.Uint32(inp[0:])
        blk[1] = binary.LittleEndian.Uint32(inp[4:])
        blk[2] = binary.LittleEndian.Uint32(inp[8:])
        blk[3] = binary.LittleEndian.Uint32(inp[12:])
    } else {
        blk[0] = binary.BigEndian.Uint32(inp[0:])
        blk[1] = binary.BigEndian.Uint32(inp[4:])
        blk[2] = binary.BigEndian.Uint32(inp[8:])
        blk[3] = binary.BigEndian.Uint32(inp[12:])
    }

    return blk
}

func uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk[0])
        binary.LittleEndian.PutUint32(sav[4:], blk[1])
        binary.LittleEndian.PutUint32(sav[8:], blk[2])
        binary.LittleEndian.PutUint32(sav[12:], blk[3])
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk[0])
        binary.BigEndian.PutUint32(sav[4:], blk[1])
        binary.BigEndian.PutUint32(sav[8:], blk[2])
        binary.BigEndian.PutUint32(sav[12:], blk[3])
    }

    return sav
}

func keyToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}
