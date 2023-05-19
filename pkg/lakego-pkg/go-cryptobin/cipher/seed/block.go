package seed

// Common functions
func getB0(a uint32) uint32 { return 0x000000ff & (a) }
func getB1(a uint32) uint32 { return 0x000000ff & (a >> 8) }
func getB2(a uint32) uint32 { return 0x000000ff & (a >> 16) }
func getB3(a uint32) uint32 { return 0x000000ff & (a >> 24) }

// SEED round function
func seedRound(l0, l1, r0, r1, k *[]uint32) {
    var t0, t1 uint32
    var t00, t11 uint64

    // F-function
    t0 = (*r0)[0] ^ (*k)[0]
    t1 = (*r1)[0] ^ (*k)[1]
    t1 ^= t0
    if t0 < 0 {
        t00 = uint64(t0&0x7fffffff | 0x80000000)
    } else {
        t00 = uint64(t0)
    }
    t1 = ss0[getB0(t1)] ^ ss1[getB1(t1)] ^ ss2[getB2(t1)] ^ ss3[getB3(t1)]
    if t1 < 0 {
        t11 = uint64(t1&0x7fffffff | 0x80000000)
    } else {
        t11 = uint64(t1)
    }
    t00 += t11
    t0 = ss0[getB0(uint32(t00))] ^ ss1[getB1(uint32(t00))] ^ ss2[getB2(uint32(t00))] ^ ss3[getB3(uint32(t00))]
    if t0 < 0 {
        t00 = uint64(t0&0x7fffffff | 0x80000000)
    } else {
        t00 = uint64(t0)
    }
    t11 += t00
    t1 = ss0[getB0(uint32(t11))] ^ ss1[getB1(uint32(t11))] ^ ss2[getB2(uint32(t11))] ^ ss3[getB3(uint32(t11))]
    if t1 < 0 {
        t11 = uint64(t1&0x7fffffff | 0x80000000)
    } else {
        t11 = uint64(t1)
    }
    t00 += t11

    // output of F function is added to left-side variable
    (*l0)[0] ^= uint32(t00)
    (*l1)[0] ^= uint32(t11)
}

func seedEncrypt(pdwRoundKey []uint32, dst, src []byte) {
    l0, l1, r0, r1 := []uint32{0x0}, []uint32{0x0}, []uint32{0x0}, []uint32{0x0}
    k := make([]uint32, 2)
    nCount := 0

    // Set up input values for encryption
    l0[0] = (uint32(src[0]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[1]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[2]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[3]) & 0x000000ff)

    l1[0] = (uint32(src[4]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[5]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[6]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[7]) & 0x000000ff)

    r0[0] = (uint32(src[8]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[9]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[10]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[11]) & 0x000000ff)

    r1[0] = (uint32(src[12]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[13]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[14]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[15]) & 0x000000ff)

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 1

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 2

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 3

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 4

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 5

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 6

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 7

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 8

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 9

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 10

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 11

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 12

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 13

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&r0, &r1, &l0, &l1, &k) // 14

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    nCount++
    seedRound(&l0, &l1, &r0, &r1, &k) // 15

    k[0] = pdwRoundKey[nCount]
    nCount++
    k[1] = pdwRoundKey[nCount]
    seedRound(&r0, &r1, &l0, &l1, &k) // 16

    // Copying output values from last round to outData
    for i := 0; i < 4; i++ {
        dst[i] = byte((r0[0] >> uint32(8*(3-i))) & 0xff)
        dst[4+i] = byte((r1[0] >> uint32(8*(3-i))) & 0xff)
        dst[8+i] = byte((l0[0] >> uint32(8*(3-i))) & 0xff)
        dst[12+i] = byte((l1[0] >> uint32(8*(3-i))) & 0xff)
    }
    return
}

// Same as encrypt, except that round keys are applied in reverse order
func seedDecrypt(pdwRoundKey []uint32, dst []byte, src []byte) {
    l0, l1, r0, r1 := []uint32{0x0}, []uint32{0x0}, []uint32{0x0}, []uint32{0x0}
    k := make([]uint32, 2)
    nCount := 31

    // Set up input values for decryption
    l0[0] = (uint32(src[0]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[1]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[2]) & 0x000000ff)
    l0[0] = ((l0[0]) << 8) ^ (uint32(src[3]) & 0x000000ff)

    l1[0] = (uint32(src[4]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[5]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[6]) & 0x000000ff)
    l1[0] = ((l1[0]) << 8) ^ (uint32(src[7]) & 0x000000ff)

    r0[0] = (uint32(src[8]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[9]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[10]) & 0x000000ff)
    r0[0] = ((r0[0]) << 8) ^ (uint32(src[11]) & 0x000000ff)

    r1[0] = (uint32(src[12]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[13]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[14]) & 0x000000ff)
    r1[0] = ((r1[0]) << 8) ^ (uint32(src[15]) & 0x000000ff)

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 1

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 2

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 3

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 4

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 5

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 6

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 7

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 8

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 9

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 10

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 11

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 12

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 13

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&r0, &r1, &l0, &l1, &k) // 14

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    nCount--
    seedRound(&l0, &l1, &r0, &r1, &k) // 15

    k[1] = pdwRoundKey[nCount]
    nCount--
    k[0] = pdwRoundKey[nCount]
    seedRound(&r0, &r1, &l0, &l1, &k) // 16

    // Copy output values from last round to outData
    for i := 0; i < 4; i++ {
        dst[i] = byte((r0[0] >> uint32(8*(3-i))) & 0xff)
        dst[4+i] = byte((r1[0] >> uint32(8*(3-i))) & 0xff)
        dst[8+i] = byte((l0[0] >> uint32(8*(3-i))) & 0xff)
        dst[12+i] = byte((l1[0] >> uint32(8*(3-i))) & 0xff)
    }
    return
}

// Functions for Key schedule
func encRoundKeyUpdate0(k, a, b, c, d *[]uint32, z int) {
    var t0, _, t00, t11 uint32
    t0 = (*a)[0]
    (*a)[0] = ((((*a)[0]) >> 8) & 0x00ffffff) ^ ((*b)[0] << 24)
    (*b)[0] = ((((*b)[0]) >> 8) & 0x00ffffff) ^ (t0 << 24)
    t00 = ((*a)[0]) + ((*c)[0]) - (kc[z])
    t11 = ((*b)[0]) + (kc[z]) - ((*d)[0])
    (*k)[0] = ss0[getB0(uint32(t00))] ^ ss1[getB1(uint32(t00))] ^ ss2[getB2(uint32(t00))] ^ ss3[getB3(uint32(t00))]
    (*k)[1] = ss0[getB0(uint32(t11))] ^ ss1[getB1(uint32(t11))] ^ ss2[getB2(uint32(t11))] ^ ss3[getB3(uint32(t11))]
}

func encRoundKeyUpdate1(k, a, b, c, d *[]uint32, z int) {
    var t0, _, t00, t11 uint32
    t0 = (*c)[0]
    (*c)[0] = (((*c)[0]) << 8) ^ ((((*d)[0]) >> 24) & 0x000000ff)
    (*d)[0] = (((*d)[0]) << 8) ^ ((t0 >> 24) & 0x000000ff)
    t00 = ((*a)[0]) + ((*c)[0]) - (kc[z])
    t11 = ((*b)[0]) + (kc[z]) - ((*d)[0])
    (*k)[0] = ss0[getB0(uint32(t00))] ^ ss1[getB1(uint32(t00))] ^ ss2[getB2(uint32(t00))] ^ ss3[getB3(uint32(t00))]
    (*k)[1] = ss0[getB0(uint32(t11))] ^ ss1[getB1(uint32(t11))] ^ ss2[getB2(uint32(t11))] ^ ss3[getB3(uint32(t11))]
}

// Key Schedule
func seedRoundKey(pbUserKey []byte) []uint32 {
    a, b, c, d, k := make([]uint32, 1), make([]uint32, 1), make([]uint32, 1), make([]uint32, 1), make([]uint32, 2)
    var t0, t1 uint32
    nCount := 2

    // Set up input values for Key Schedule
    a[0] = (uint32(pbUserKey[0]) & 0x000000ff)
    a[0] = (a[0] << 8) ^ (uint32(pbUserKey[1]) & 0x000000ff)
    a[0] = (a[0] << 8) ^ (uint32(pbUserKey[2]) & 0x000000ff)
    a[0] = (a[0] << 8) ^ (uint32(pbUserKey[3]) & 0x000000ff)

    b[0] = (uint32(pbUserKey[4]) & 0x000000ff)
    b[0] = (b[0] << 8) ^ (uint32(pbUserKey[5]) & 0x000000ff)
    b[0] = (b[0] << 8) ^ (uint32(pbUserKey[6]) & 0x000000ff)
    b[0] = (b[0] << 8) ^ (uint32(pbUserKey[7]) & 0x000000ff)

    c[0] = (uint32(pbUserKey[8]) & 0x000000ff)
    c[0] = (c[0] << 8) ^ (uint32(pbUserKey[9]) & 0x000000ff)
    c[0] = (c[0] << 8) ^ (uint32(pbUserKey[10]) & 0x000000ff)
    c[0] = (c[0] << 8) ^ (uint32(pbUserKey[11]) & 0x000000ff)

    d[0] = (uint32(pbUserKey[12]) & 0x000000ff)
    d[0] = (d[0] << 8) ^ (uint32(pbUserKey[13]) & 0x000000ff)
    d[0] = (d[0] << 8) ^ (uint32(pbUserKey[14]) & 0x000000ff)
    d[0] = (d[0] << 8) ^ (uint32(pbUserKey[15]) & 0x000000ff)

    t0 = (a[0]) + (c[0]) - (kc[0])
    t1 = (b[0]) - (d[0]) + (kc[0])

    pdwRoundKey := make([]uint32, 32)

    pdwRoundKey[0] = ss0[getB0(uint32(t0))] ^ ss1[getB1(uint32(t0))] ^ ss2[getB2(uint32(t0))] ^ ss3[getB3(uint32(t0))]
    pdwRoundKey[1] = ss0[getB0(uint32(t1))] ^ ss1[getB1(uint32(t1))] ^ ss2[getB2(uint32(t1))] ^ ss3[getB3(uint32(t1))]

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 1)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 2)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 3)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 4)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 5)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 6)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 7)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 8)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 9)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 10)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 11)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 12)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 13)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate1(&k, &a, &b, &c, &d, 14)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]
    nCount++

    encRoundKeyUpdate0(&k, &a, &b, &c, &d, 15)
    pdwRoundKey[nCount] = k[0]
    nCount++
    pdwRoundKey[nCount] = k[1]

    return pdwRoundKey
}
