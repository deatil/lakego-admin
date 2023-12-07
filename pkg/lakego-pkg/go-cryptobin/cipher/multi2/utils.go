package multi2

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func bytesToUint32s(b []byte) []uint32 {
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

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func ROL(x uint32, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func ROR(x uint32, n uint32) uint32 {
    return ROL(x, 32 - n);
}

func pi1(p []uint32) {
    p[1] ^= p[0]
}

func pi2(p []uint32, k []uint32) {
   var t uint32

   t = (p[1] + k[0]) & 0xFFFFFFFF
   t = (ROL(t, 1) + t - 1)  & 0xFFFFFFFF
   t = (ROL(t, 4) ^ t)  & 0xFFFFFFFF

   p[0] ^= t
}

func pi3(p []uint32, k []uint32) {
   var t uint32

   t = p[0] + k[1]

   t = (ROL(t, 2) + t + 1)  & 0xFFFFFFFF
   t = (ROL(t, 8) ^ t)  & 0xFFFFFFFF
   t = (t + k[2])  & 0xFFFFFFFF
   t = (ROL(t, 1) - t)  & 0xFFFFFFFF
   t = ROL(t, 16) ^ (p[0] | t)

   p[1] ^= t
}

func pi4(p []uint32, k []uint32) {
   var t uint32

   t = (p[1] + k[3])  & 0xFFFFFFFF
   t = (ROL(t, 2) + t + 1)  & 0xFFFFFFFF

   p[0] ^= t
}

func setup(dk []uint32, k []uint32, uk []uint32) {
    var n, t int32
    var p [2]uint32

    p[0] = dk[0]
    p[1] = dk[1]

    t = 4
    n = 0

    pi1(p[:])

    pi2(p[:], k)
    uk[n] = p[0]
    n++

    pi3(p[:], k)
    uk[n] = p[1]
    n++

    pi4(p[:], k)
    uk[n] = p[0]
    n++

    pi1(p[:])
    uk[n] = p[1]
    n++

    pi2(p[:], k[t:])
    uk[n] = p[0]
    n++

    pi3(p[:], k[t:])
    uk[n] = p[1]
    n++

    pi4(p[:], k[t:])
    uk[n] = p[0]
    n++

    pi1(p[:])
    uk[n] = p[1]
    n++
}

func encrypt(p []uint32, N int32, uk []uint32) {
    var n, t int32

    t, n = 0, 0

    for {
        pi1(p)
        n++
        if n == N {
            break
        }

        pi2(p, uk[t:])
        n++
        if n == N {
            break
        }

        pi3(p, uk[t:])
        n++
        if n == N {
            break
        }

        pi4(p, uk[t:])
        n++
        if n == N {
            break
        }

        t ^= 4
    }
}

func decrypt(p []uint32, N int32, uk []uint32) {
    var n, t int32
    var nn int32

    t = 4*(((N-1)>>2)&1)
    n = N

    for {
        if n <= 4 {
            nn = n
        } else {
            nn = ((n-1)%4)+1
        }

        switch nn {
            case 4:
                pi4(p, uk[t:])
                n--
                fallthrough
            case 3:
                pi3(p, uk[t:])
                n--
                fallthrough
            case 2:
                pi2(p, uk[t:])
                n--
                fallthrough
            case 1:
                pi1(p)
                n--
            case 0:
                return
        }

        t ^= 4
    }
}
