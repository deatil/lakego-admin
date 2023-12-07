package clefia

/* S0 (8-bit S-box based on four 4-bit S-boxes) */
var clefia_s0 = [256]byte{
  0x57, 0x49, 0xd1, 0xc6, 0x2f, 0x33, 0x74, 0xfb,
  0x95, 0x6d, 0x82, 0xea, 0x0e, 0xb0, 0xa8, 0x1c,
  0x28, 0xd0, 0x4b, 0x92, 0x5c, 0xee, 0x85, 0xb1,
  0xc4, 0x0a, 0x76, 0x3d, 0x63, 0xf9, 0x17, 0xaf,
  0xbf, 0xa1, 0x19, 0x65, 0xf7, 0x7a, 0x32, 0x20,
  0x06, 0xce, 0xe4, 0x83, 0x9d, 0x5b, 0x4c, 0xd8,
  0x42, 0x5d, 0x2e, 0xe8, 0xd4, 0x9b, 0x0f, 0x13,
  0x3c, 0x89, 0x67, 0xc0, 0x71, 0xaa, 0xb6, 0xf5,
  0xa4, 0xbe, 0xfd, 0x8c, 0x12, 0x00, 0x97, 0xda,
  0x78, 0xe1, 0xcf, 0x6b, 0x39, 0x43, 0x55, 0x26,
  0x30, 0x98, 0xcc, 0xdd, 0xeb, 0x54, 0xb3, 0x8f,
  0x4e, 0x16, 0xfa, 0x22, 0xa5, 0x77, 0x09, 0x61,
  0xd6, 0x2a, 0x53, 0x37, 0x45, 0xc1, 0x6c, 0xae,
  0xef, 0x70, 0x08, 0x99, 0x8b, 0x1d, 0xf2, 0xb4,
  0xe9, 0xc7, 0x9f, 0x4a, 0x31, 0x25, 0xfe, 0x7c,
  0xd3, 0xa2, 0xbd, 0x56, 0x14, 0x88, 0x60, 0x0b,
  0xcd, 0xe2, 0x34, 0x50, 0x9e, 0xdc, 0x11, 0x05,
  0x2b, 0xb7, 0xa9, 0x48, 0xff, 0x66, 0x8a, 0x73,
  0x03, 0x75, 0x86, 0xf1, 0x6a, 0xa7, 0x40, 0xc2,
  0xb9, 0x2c, 0xdb, 0x1f, 0x58, 0x94, 0x3e, 0xed,
  0xfc, 0x1b, 0xa0, 0x04, 0xb8, 0x8d, 0xe6, 0x59,
  0x62, 0x93, 0x35, 0x7e, 0xca, 0x21, 0xdf, 0x47,
  0x15, 0xf3, 0xba, 0x7f, 0xa6, 0x69, 0xc8, 0x4d,
  0x87, 0x3b, 0x9c, 0x01, 0xe0, 0xde, 0x24, 0x52,
  0x7b, 0x0c, 0x68, 0x1e, 0x80, 0xb2, 0x5a, 0xe7,
  0xad, 0xd5, 0x23, 0xf4, 0x46, 0x3f, 0x91, 0xc9,
  0x6e, 0x84, 0x72, 0xbb, 0x0d, 0x18, 0xd9, 0x96,
  0xf0, 0x5f, 0x41, 0xac, 0x27, 0xc5, 0xe3, 0x3a,
  0x81, 0x6f, 0x07, 0xa3, 0x79, 0xf6, 0x2d, 0x38,
  0x1a, 0x44, 0x5e, 0xb5, 0xd2, 0xec, 0xcb, 0x90,
  0x9a, 0x36, 0xe5, 0x29, 0xc3, 0x4f, 0xab, 0x64,
  0x51, 0xf8, 0x10, 0xd7, 0xbc, 0x02, 0x7d, 0x8e,
}

/* S1 (8-bit S-box based on inverse function) */
var clefia_s1 = [256]byte{
  0x6c, 0xda, 0xc3, 0xe9, 0x4e, 0x9d, 0x0a, 0x3d,
  0xb8, 0x36, 0xb4, 0x38, 0x13, 0x34, 0x0c, 0xd9,
  0xbf, 0x74, 0x94, 0x8f, 0xb7, 0x9c, 0xe5, 0xdc,
  0x9e, 0x07, 0x49, 0x4f, 0x98, 0x2c, 0xb0, 0x93,
  0x12, 0xeb, 0xcd, 0xb3, 0x92, 0xe7, 0x41, 0x60,
  0xe3, 0x21, 0x27, 0x3b, 0xe6, 0x19, 0xd2, 0x0e,
  0x91, 0x11, 0xc7, 0x3f, 0x2a, 0x8e, 0xa1, 0xbc,
  0x2b, 0xc8, 0xc5, 0x0f, 0x5b, 0xf3, 0x87, 0x8b,
  0xfb, 0xf5, 0xde, 0x20, 0xc6, 0xa7, 0x84, 0xce,
  0xd8, 0x65, 0x51, 0xc9, 0xa4, 0xef, 0x43, 0x53,
  0x25, 0x5d, 0x9b, 0x31, 0xe8, 0x3e, 0x0d, 0xd7,
  0x80, 0xff, 0x69, 0x8a, 0xba, 0x0b, 0x73, 0x5c,
  0x6e, 0x54, 0x15, 0x62, 0xf6, 0x35, 0x30, 0x52,
  0xa3, 0x16, 0xd3, 0x28, 0x32, 0xfa, 0xaa, 0x5e,
  0xcf, 0xea, 0xed, 0x78, 0x33, 0x58, 0x09, 0x7b,
  0x63, 0xc0, 0xc1, 0x46, 0x1e, 0xdf, 0xa9, 0x99,
  0x55, 0x04, 0xc4, 0x86, 0x39, 0x77, 0x82, 0xec,
  0x40, 0x18, 0x90, 0x97, 0x59, 0xdd, 0x83, 0x1f,
  0x9a, 0x37, 0x06, 0x24, 0x64, 0x7c, 0xa5, 0x56,
  0x48, 0x08, 0x85, 0xd0, 0x61, 0x26, 0xca, 0x6f,
  0x7e, 0x6a, 0xb6, 0x71, 0xa0, 0x70, 0x05, 0xd1,
  0x45, 0x8c, 0x23, 0x1c, 0xf0, 0xee, 0x89, 0xad,
  0x7a, 0x4b, 0xc2, 0x2f, 0xdb, 0x5a, 0x4d, 0x76,
  0x67, 0x17, 0x2d, 0xf4, 0xcb, 0xb1, 0x4a, 0xa8,
  0xb5, 0x22, 0x47, 0x3a, 0xd5, 0x10, 0x4c, 0x72,
  0xcc, 0x00, 0xf9, 0xe0, 0xfd, 0xe2, 0xfe, 0xae,
  0xf8, 0x5f, 0xab, 0xf1, 0x1b, 0x42, 0x81, 0xd6,
  0xbe, 0x44, 0x29, 0xa6, 0x57, 0xb9, 0xaf, 0xf2,
  0xd4, 0x75, 0x66, 0xbb, 0x68, 0x9f, 0x50, 0x02,
  0x01, 0x3c, 0x7f, 0x8d, 0x1a, 0x88, 0xbd, 0xac,
  0xf7, 0xe4, 0x79, 0x96, 0xa2, 0xfc, 0x6d, 0xb2,
  0x6b, 0x03, 0xe1, 0x2e, 0x7d, 0x14, 0x95, 0x1d,
}

func ByteXor(dst []byte, a []byte, b []byte, bytelen int32) {
    var n int32
    for n = 0; n < bytelen; n++ {
        dst[n] = a[n] ^ b[n]
    }
}

func ClefiaMul2(x byte) byte {
  /* multiplication over GF(2^8) (p(x) = '11d') */
  if (x & 0x80) > 0 {
    x ^= 0x0e
  }

  return (x << 1) | (x >> 7)
}

func ClefiaMul4(_x byte) byte {
    return ClefiaMul2(ClefiaMul2(_x))
}

func ClefiaMul6(_x byte) byte {
    return ClefiaMul2(_x) ^ ClefiaMul4(_x)
}

func ClefiaMul8(_x byte) byte {
    return ClefiaMul2(ClefiaMul4(_x))
}

func ClefiaMulA(_x byte) byte {
    return ClefiaMul2(_x) ^ ClefiaMul8(_x)
}

func ClefiaF0Xor(dst []byte, src []byte, rk []byte) {
  var x, y, z [4]byte

  /* F0 */
  /* Key addition */
  ByteXor(x[:], src, rk, 4)

  /* Substitution layer */
  z[0] = clefia_s0[x[0]]
  z[1] = clefia_s1[x[1]]
  z[2] = clefia_s0[x[2]]
  z[3] = clefia_s1[x[3]]

  /* Diffusion layer (M0) */
  y[0] =            z[0]  ^ ClefiaMul2(z[1]) ^ ClefiaMul4(z[2]) ^ ClefiaMul6(z[3])
  y[1] = ClefiaMul2(z[0]) ^            z[1]  ^ ClefiaMul6(z[2]) ^ ClefiaMul4(z[3])
  y[2] = ClefiaMul4(z[0]) ^ ClefiaMul6(z[1]) ^            z[2]  ^ ClefiaMul2(z[3])
  y[3] = ClefiaMul6(z[0]) ^ ClefiaMul4(z[1]) ^ ClefiaMul2(z[2]) ^            z[3]

  /* Xoring after F0 */
  copy(dst[0:], src[:4])

  ByteXor(dst[4:], src[4:], y[:], 4)
}

func ClefiaF1Xor(dst []byte, src []byte, rk []byte) {
  var x, y, z [4]byte

  /* F1 */
  /* Key addition */
  ByteXor(x[:], src, rk, 4)

  /* Substitution layer */
  z[0] = clefia_s1[x[0]]
  z[1] = clefia_s0[x[1]]
  z[2] = clefia_s1[x[2]]
  z[3] = clefia_s0[x[3]]

  /* Diffusion layer (M1) */
  y[0] =            z[0]  ^ ClefiaMul8(z[1]) ^ ClefiaMul2(z[2]) ^ ClefiaMulA(z[3])
  y[1] = ClefiaMul8(z[0]) ^            z[1]  ^ ClefiaMulA(z[2]) ^ ClefiaMul2(z[3])
  y[2] = ClefiaMul2(z[0]) ^ ClefiaMulA(z[1]) ^            z[2]  ^ ClefiaMul8(z[3])
  y[3] = ClefiaMulA(z[0]) ^ ClefiaMul2(z[1]) ^ ClefiaMul8(z[2]) ^            z[3]

  /* Xoring after F1 */
  copy(dst[0:], src[:4])

  ByteXor(dst[4:], src[4:], y[:], 4)
}

func ClefiaGfn4(y []byte, x []byte, rk []byte, r int32) {
  var fin, fout [16]byte

  copy(fin[0:], x[:16])

  var i int32

  for i = r; i > 0; i-- {
    ClefiaF0Xor(fout[0:], fin[0:], rk[0:])
    ClefiaF1Xor(fout[8:], fin[8:], rk[4:])
    rk = rk[8:]

    if r > 0 { /* swapping for encryption */
      copy(fin[0:], fout[4:16])
      copy(fin[12:], fout[0:4])
    }
  }

  copy(y[0:], fout[0:16])
}

func ClefiaGfn8(y []byte, x []byte, rk []byte, r int32) {
  var fin, fout [32]byte

  copy(fin[0:], x[0:32])

  var i int32

  for i = r; i > 0; i-- {
    ClefiaF0Xor(fout[0:],  fin[0:],  rk[0:])
    ClefiaF1Xor(fout[8:],  fin[8:],  rk[4:])
    ClefiaF0Xor(fout[16:], fin[16:], rk[8:])
    ClefiaF1Xor(fout[24:], fin[24:], rk[12:])
    rk = rk[16:]

    if r > 0 { /* swapping for encryption */
      copy(fin[0:], fout[4:32])
      copy(fin[28:], fout[0:4])
    }
  }
  copy(y[0:], fout[0:32])
}

func ClefiaGfn4Inv(y []byte, x []byte, rk []byte, r int32) {
  var fin, fout [16]byte

  copy(fin[0:], x[0:16])

  var i int32
  for i = r; i > 0; i-- {
    ClefiaF0Xor(fout[0:], fin[0:], rk[(i - 1) * 8 + 0:])
    ClefiaF1Xor(fout[8:], fin[8:], rk[(i - 1) * 8 + 4:])

    if r > 0 { /* swapping for decryption */
      copy(fin[0:], fout[12:16])
      copy(fin[4:], fout[0:12])
    }
  }

  copy(y[0:], fout[0:16])
}

func ClefiaDoubleSwap(lk []byte) {
  var t [16]byte

  t[0]  = (lk[0] << 7) | (lk[1]  >> 1)
  t[1]  = (lk[1] << 7) | (lk[2]  >> 1)
  t[2]  = (lk[2] << 7) | (lk[3]  >> 1)
  t[3]  = (lk[3] << 7) | (lk[4]  >> 1)
  t[4]  = (lk[4] << 7) | (lk[5]  >> 1)
  t[5]  = (lk[5] << 7) | (lk[6]  >> 1)
  t[6]  = (lk[6] << 7) | (lk[7]  >> 1)
  t[7]  = (lk[7] << 7) | (lk[15] & 0x7f)

  t[8]  = (lk[8]  >> 7) | (lk[0]  & 0xfe)
  t[9]  = (lk[9]  >> 7) | (lk[8]  << 1)
  t[10] = (lk[10] >> 7) | (lk[9]  << 1)
  t[11] = (lk[11] >> 7) | (lk[10] << 1)
  t[12] = (lk[12] >> 7) | (lk[11] << 1)
  t[13] = (lk[13] >> 7) | (lk[12] << 1)
  t[14] = (lk[14] >> 7) | (lk[13] << 1)
  t[15] = (lk[15] >> 7) | (lk[14] << 1)

  copy(lk[0:], t[0:16])
}

func ClefiaConSet(con []byte, iv []byte, lk int32) {
  var t [2]byte
  var tmp byte

  copy(t[0:], iv[0:2])

  var i int32
  for i = lk; i > 0; i-- {
    con[0] = t[0] ^ 0xb7 /* P_16 = 0xb7e1 (natural logarithm) */
    con[1] = t[1] ^ 0xe1
    con[2] = ^((t[0] << 1) | (t[1] >> 7))
    con[3] = ^((t[1] << 1) | (t[0] >> 7))
    con[4] = ^t[0] ^ 0x24 /* Q_16 = 0x243f (circle ratio) */
    con[5] = ^t[1] ^ 0x3f
    con[6] = t[1]
    con[7] = t[0]

    con = con[8:]

    /* updating T */
    if (t[1] & 0x01) > 0 {
      t[0] ^= 0xa8
      t[1] ^= 0x30
    }

    tmp = t[0] << 7
    t[0] = (t[0] >> 1) | (t[1] << 7)
    t[1] = (t[1] >> 1) | tmp
  }
}

func ClefiaKeySet128(rk []byte, skey []byte) {
  var iv = [2]byte{0x42, 0x8a} /* cubic root of 2 */
  var lk [16]byte
  var con128 [240]byte
  var i int32

  /* generating CONi^(128) (0 <= i < 60, lk = 30) */
  ClefiaConSet(con128[:], iv[:], 30)
  /* GFN_{4,12} (generating L from K) */
  ClefiaGfn4(lk[:], skey, con128[:], 12)

  copy(rk[0:], skey[0:8]) /* initial whitening key (WK0, WK1) */
  rk = rk[8:]
  for i = 0; i < 9; i++ { /* round key (RKi (0 <= i < 36)) */
    ByteXor(rk, lk[:], con128[i * 16 + (4 * 24):], 16)

    if (i % 2) > 0 {
      ByteXor(rk, rk, skey, 16) /* Xoring K */
    }

    ClefiaDoubleSwap(lk[:]) /* Updating L (DoubleSwap function) */
    rk = rk[16:]
  }

  copy(rk[0:], skey[8:16]) /* final whitening key (WK2, WK3) */
}

func ClefiaKeySet192(rk []byte, skey []byte) {
  var iv = [2]byte{0x71, 0x37} /* cubic root of 3 */
  var skey256 [32]byte
  var lk [32]byte
  var con192 [4 * 84]byte
  var i int32

  copy(skey256[0:], skey[0:24])
  for i = 0; i < 8; i++ {
    skey256[i + 24] = ^skey[i]
  }

  /* generating CONi^(192) (0 <= i < 84, lk = 42) */
  ClefiaConSet(con192[:], iv[:], 42)
  /* GFN_{8,10} (generating L from K) */
  ClefiaGfn8(lk[:], skey256[:], con192[:], 10)

  ByteXor(rk, skey256[:], skey256[16:], 8) /* initial whitening key (WK0, WK1) */
  rk = rk[8:]

  for i = 0; i < 11; i++ { /* round key (RKi (0 <= i < 44)) */
    if ((i / 2) % 2) > 0 {
      ByteXor(rk, lk[16:], con192[i * 16 + (4 * 40):], 16) /* LR */
      if (i % 2) > 0 {
        ByteXor(rk, rk, skey256[0:],  16) /* Xoring KL */
      }
      ClefiaDoubleSwap(lk[16:]) /* updating LR */
    } else {
      ByteXor(rk, lk[0:],  con192[i * 16 + (4 * 40):], 16) /* LL */
      if (i % 2) > 0 {
        ByteXor(rk, rk, skey256[16:], 16) /* Xoring KR */
      }

      ClefiaDoubleSwap(lk[0:])  /* updating LL */
    }

    rk = rk[16:]
  }

  ByteXor(rk, skey256[8:], skey256[24:], 8) /* final whitening key (WK2, WK3) */
}

func ClefiaKeySet256(rk []byte, skey []byte) {
  var iv = [2]byte{0xb5, 0xc0} /* cubic root of 5 */
  var lk [32]byte
  var con256 [4 * 92]byte
  var i int32

  /* generating CONi^(256) (0 <= i < 92, lk = 46) */
  ClefiaConSet(con256[:], iv[:], 46)
  /* GFN_{8,10} (generating L from K) */
  ClefiaGfn8(lk[:], skey, con256[:], 10)

  ByteXor(rk, skey, skey[16:], 8) /* initial whitening key (WK0, WK1) */
  rk = rk[8:]

  for i = 0; i < 13; i++ { /* round key (RKi (0 <= i < 52)) */
    if ((i / 2) % 2) > 0 {
      ByteXor(rk, lk[16:], con256[i * 16 + (4 * 40):], 16) /* LR */
      if (i % 2) > 0 {
        ByteXor(rk, rk, skey[0:],  16) /* Xoring KL */
      }
      ClefiaDoubleSwap(lk[16:]) /* updating LR */
    } else {
      ByteXor(rk, lk[0:],  con256[i * 16 + (4 * 40):], 16) /* LL */
      if (i % 2) > 0 {
        ByteXor(rk, rk, skey[16:], 16) /* Xoring KR */
      }
      ClefiaDoubleSwap(lk[:])  /* updating LL */
    }
    rk = rk[16:]
  }
  ByteXor(rk, skey[8:], skey[24:], 8) /* final whitening key (WK2, WK3) */
}

func ClefiaKeySet(rk []byte, skey []byte, key_bitlen int32) int32 {
    switch key_bitlen {
        case 128:
            ClefiaKeySet128(rk, skey)
            return 18;
        case 192:
            ClefiaKeySet192(rk, skey);
            return 22;
        case 256:
            ClefiaKeySet256(rk, skey);
            return 26;
    }

    return 0; /* invalid key_bitlen */
}

func ClefiaEncrypt(ct []byte, pt []byte, rk []byte, r int32) {
  var rin, rout [16]byte

  copy(rin[0:], pt[:16])

  ByteXor(rin[4:],  rin[4:],  rk[0:], 4) /* initial key whitening */
  ByteXor(rin[12:], rin[12:], rk[4:], 4)
  rk = rk[8:]

  ClefiaGfn4(rout[:], rin[:], rk, r) /* GFN_{4,r} */

  copy(ct[0:], rout[:16])

  ByteXor(ct[4:],  ct[4:],  rk[r * 8 + 0:], 4) /* final key whitening */
  ByteXor(ct[12:], ct[12:], rk[r * 8 + 4:], 4)
}

func ClefiaDecrypt(pt []byte, ct []byte, rk []byte, r int32) {
  var rin, rout [16]byte

  copy(rin[0:], ct[:16])

  ByteXor(rin[4:],  rin[4:],  rk[r * 8 + 8:],  4) /* initial key whitening */
  ByteXor(rin[12:], rin[12:], rk[r * 8 + 12:], 4)

  ClefiaGfn4Inv(rout[:], rin[:], rk[8:], r); /* GFN^{-1}_{4,r} */

  copy(pt[0:], rout[:16])

  ByteXor(pt[4:],  pt[4:],  rk[0:], 4) /* final key whitening */
  ByteXor(pt[12:], pt[12:], rk[4:], 4)
}
