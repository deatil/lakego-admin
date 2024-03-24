package ascon

import (
    "encoding/binary"
)

type state struct {
    x0, x1, x2, x3, x4 uint64
}

func (s *state) init(iv, k0, k1, n0, n1 uint64) {
    s.x0 = iv
    s.x1 = k0
    s.x2 = k1
    s.x3 = n0
    s.x4 = n1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) finalize128a(k0, k1 uint64) {
    s.x2 ^= k0
    s.x3 ^= k1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) additionalData128a(ad []byte) {
    if len(ad) > 0 {
        n := len(ad) &^ (BlockSize128a - 1)
        if n > 0 {
            additionalData128a(s, ad[:n])
            ad = ad[n:]
        }
        if len(ad) >= 8 {
            s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
            s.x1 ^= be64n(ad[8:])
            s.x1 ^= pad(len(ad) - 8)
        } else {
            s.x0 ^= be64n(ad)
            s.x0 ^= pad(len(ad))
        }
        p8(s)
    }

    s.x4 ^= 1
}

func (s *state) encrypt128a(dst, src []byte) {
    n := len(src) &^ (BlockSize128a - 1)
    if n > 0 {
        encryptBlocks128a(s, dst[:n], src[:n])
        src = src[n:]
        dst = dst[n:]
    }

    if len(src) >= 8 {
        s.x0 ^= binary.BigEndian.Uint64(src[0:8])
        s.x1 ^= be64n(src[8:])
        s.x1 ^= pad(len(src) - 8)
        binary.BigEndian.PutUint64(dst[0:8], s.x0)
        put64n(dst[8:], s.x1)
    } else {
        s.x0 ^= be64n(src)
        put64n(dst, s.x0)
        s.x0 ^= pad(len(src))
    }
}

func (s *state) decrypt128a(dst, src []byte) {
    n := len(src) &^ (BlockSize128a - 1)
    if n > 0 {
        decryptBlocks128a(s, dst[:n], src[:n])
        src = src[n:]
        dst = dst[n:]
    }

    if len(src) >= 8 {
        c0 := binary.BigEndian.Uint64(src[0:8])
        c1 := be64n(src[8:])
        binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
        put64n(dst[8:], s.x1^c1)
        s.x0 = c0
        s.x1 = mask(s.x1, len(src)-8)
        s.x1 |= c1
        s.x1 ^= pad(len(src) - 8)
    } else {
        c0 := be64n(src)
        put64n(dst, s.x0^c0)
        s.x0 = mask(s.x0, len(src))
        s.x0 |= c0
        s.x0 ^= pad(len(src))
    }
}

func (s *state) finalize128(k0, k1 uint64) {
    s.x1 ^= k0
    s.x2 ^= k1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) additionalData128(ad []byte) {
    if len(ad) > 0 {
        for len(ad) >= BlockSize128 {
            s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
            p6(s)
            ad = ad[BlockSize128:]
        }
        s.x0 ^= be64n(ad)
        s.x0 ^= pad(len(ad))
        p6(s)
    }
    s.x4 ^= 1
}

func (s *state) encrypt128(dst, src []byte) {
    for len(src) >= BlockSize128 {
        s.x0 ^= binary.BigEndian.Uint64(src[0:8])
        binary.BigEndian.PutUint64(dst[0:8], s.x0)
        p6(s)
        src = src[BlockSize128:]
        dst = dst[BlockSize128:]
    }

    s.x0 ^= be64n(src)
    put64n(dst, s.x0)
    s.x0 ^= pad(len(src))
}

func (s *state) decrypt128(dst, src []byte) {
    for len(src) >= BlockSize128 {
        c := binary.BigEndian.Uint64(src[0:8])
        binary.BigEndian.PutUint64(dst[0:8], s.x0^c)
        s.x0 = c
        p6(s)
        src = src[BlockSize128:]
        dst = dst[BlockSize128:]
    }

    c := be64n(src)
    put64n(dst, s.x0^c)
    s.x0 = mask(s.x0, len(src))
    s.x0 |= c
    s.x0 ^= pad(len(src))
}

func (s *state) tag(dst []byte) {
    binary.BigEndian.PutUint64(dst[0:8], s.x3)
    binary.BigEndian.PutUint64(dst[8:16], s.x4)
}
