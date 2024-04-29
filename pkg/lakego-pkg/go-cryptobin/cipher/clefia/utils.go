package clefia

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
