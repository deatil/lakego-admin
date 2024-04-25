package xxh3

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func getu32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func putu32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func putu64be(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

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

func rotl32(x uint32, n uint) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr32(x uint32, n uint) uint32 {
    return rotl32(x, 32 - n)
}

func rotl64(x uint64, n uint) uint64 {
    return bits.RotateLeft64(x, int(n))
}

func rotr64(x uint64, n uint) uint64 {
    return rotl64(x, 64 - n)
}

func swap32(x uint32) uint32 {
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff )
}

func swap64(x uint64) uint64 {
    return  ((x << 56) & 0xff00000000000000) |
            ((x << 40) & 0x00ff000000000000) |
            ((x << 24) & 0x0000ff0000000000) |
            ((x << 8)  & 0x000000ff00000000) |
            ((x >> 8)  & 0x00000000ff000000) |
            ((x >> 24) & 0x0000000000ff0000) |
            ((x >> 40) & 0x000000000000ff00) |
            ((x >> 56) & 0x00000000000000ff)
}

// =========

func xorshift64(v64 uint64, shift int) uint64 {
    return v64 ^ (v64 >> shift)
}

func rrmxmx(h64, len uint64) uint64 {
    h64 ^= rotl64(h64, 49) ^ rotl64(h64, 24)
    h64 *= PRIME_MX2
    h64 ^= (h64 >> 35) + len
    h64 *= PRIME_MX2
    return xorshift64(h64, 28)
}

func avalanche(h64 uint64) uint64 {
    h64  = xorshift64(h64, 37)
    h64 *= PRIME_MX1
    h64  = xorshift64(h64, 32)
    return h64
}

func mult32to64(x uint32, y uint32) uint64 {
    return uint64(x & 0xFFFFFFFF) * uint64(y & 0xFFFFFFFF)
}

func mult32to64_add64(lhs, rhs, acc uint64) uint64 {
    return mult32to64(uint32(lhs), uint32(rhs)) + acc
}

func mult64to128(lhs, rhs uint64) Uint128 {
    /* First calculate all of the cross products. */
    lo_lo := mult32to64(uint32(lhs & 0xFFFFFFFF), uint32(rhs & 0xFFFFFFFF))
    hi_lo := mult32to64(uint32(lhs >> 32),        uint32(rhs & 0xFFFFFFFF))
    lo_hi := mult32to64(uint32(lhs & 0xFFFFFFFF), uint32(rhs >> 32))
    hi_hi := mult32to64(uint32(lhs >> 32),        uint32(rhs >> 32))

    /* Now add the products together. These will never overflow. */
    cross := (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi
    upper := (hi_lo >> 32) + (cross >> 32)        + hi_hi
    lower := (cross << 32) | (lo_lo & 0xFFFFFFFF)

    var r128 Uint128
    r128.Low  = lower
    r128.High = upper

    return r128
}

func mul128_fold64(lhs, rhs uint64) uint64 {
    product := mult64to128(lhs, rhs)
    return product.Low ^ product.High
}

// =========

func scalarRound(
    acc    []uint64,
    input  []byte,
    secret []byte,
    lane   int,
) {
    data_val := getu64(input[lane * 8:])
    data_key := data_val ^ getu64(secret[lane * 8:])

    acc[lane ^ 1] += data_val;
    acc[lane] = mult32to64_add64(data_key, data_key >> 32, acc[lane])
}

func accumulate_512(acc []uint64, input []byte, secret []byte) {
    for i := 0; i < 8; i++ {
        scalarRound(acc, input, secret, i)
    }
}

func mix2Accs(acc []uint64, secret []byte) uint64 {
    return  mul128_fold64(
               acc[0] ^ getu64(secret[0:]),
               acc[1] ^ getu64(secret[8:]),
            )
}

func mergeAccs(acc []uint64, secret []byte, start uint64) uint64 {
    result64 := start

    for i := 0; i < 4; i++ {
        result64 += mix2Accs(acc[2*i:], secret[16*i:])
    }

    return avalanche(result64)
}

func accumulate(acc []uint64, input []byte, secret []byte, nbStripes int) {
    var in []byte
    for n := 0; n < nbStripes; n++ {
        in = input[n*STRIPE_LEN:]
        accumulate_512(acc, in, secret[n*SECRET_CONSUME_RATE:])
    }
}

func scalarScrambleRound(
    acc    []uint64,
    secret []byte,
    lane   int,
) {
    key64 := getu64(secret[lane * 8:])
    acc64 := acc[lane]

    acc64  = xorshift64(acc64, 47)
    acc64 ^= key64
    acc64 *= uint64(PRIME32_1)

    acc[lane] = acc64
}

func scrambleAcc(acc []uint64, secret []byte) {
    for i := 0; i < 8; i++ {
        scalarScrambleRound(acc, secret, i)
    }
}

// =========

func len_1to3_64b(input []byte, secret []byte, seed uint64) uint64 {
    len := len(input)

    c1 := input[0];
    c2 := input[len >> 1]
    c3 := input[len - 1]

    combined := (uint32(c1) << 16) |
                (uint32(c2) << 24) |
                (uint32(c3) <<  0) |
                (uint32(len) << 8)
    bitflip := uint64(getu32(secret) ^ getu32(secret[4:])) + seed
    keyed := uint64(combined) ^ bitflip

    return avalanche(keyed)
}

func len_4to8_64b(input []byte, secret []byte, seed uint64) uint64 {
    len := len(input)

    seed ^= uint64(swap32(uint32(seed))) << 32

    input1 := getu32(input)
    input2 := getu32(input[len - 4:])

    bitflip := (getu64(secret[8:]) ^ getu64(secret[16:])) - seed
    input64 := uint64(input2) + (uint64(input1) << 32)
    keyed := input64 ^ bitflip

    return rrmxmx(keyed, uint64(len))
}

func len_9to16_64b(input []byte, secret []byte, seed uint64) uint64 {
    len := len(input)

    bitflip1 := (getu64(secret[24:]) ^ getu64(secret[32:])) + seed
    bitflip2 := (getu64(secret[40:]) ^ getu64(secret[48:])) - seed

    input_lo := getu64(input[0      :]) ^ bitflip1
    input_hi := getu64(input[len - 8:]) ^ bitflip2

    acc := uint64(len) + swap64(input_lo) + input_hi +
            mul128_fold64(input_lo, input_hi)

    return avalanche(acc)
}

func len_0to16_64b(input []byte, secret []byte, seed uint64) uint64 {
    if len(input) > 8 {
        return len_9to16_64b(input, secret, seed)
    }
    if len(input) >= 4 {
        return len_4to8_64b(input, secret, seed)
    }
    if len(input) > 0 {
        return len_1to3_64b(input, secret, seed)
    }

    return avalanche(seed ^ (getu64(secret[56:]) ^ getu64(secret[64:])))
}

func mix16B(input []byte, secret []byte, seed64 uint64) uint64 {
    input_lo := getu64(input)
    input_hi := getu64(input[8:])

    return mul128_fold64(
        input_lo ^ (getu64(secret[0:]) + seed64),
        input_hi ^ (getu64(secret[8:]) - seed64),
    )
}

func len_17to128_64b(input []byte, secret []byte, seed uint64) uint64 {
    len := len(input)

    acc := uint64(len) * PRIME64_1

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc += mix16B(input[48:], secret[96:], seed)
                acc += mix16B(input[len-64:], secret[112:], seed)
            }

            acc += mix16B(input[32:], secret[64:], seed)
            acc += mix16B(input[len-48:], secret[80:], seed)
        }

        acc += mix16B(input[16:], secret[32:], seed)
        acc += mix16B(input[len-32:], secret[48:], seed)
    }

    acc += mix16B(input[0:], secret[0:], seed)
    acc += mix16B(input[len-16:], secret[16:], seed)

    return avalanche(acc)
}

func len_129to240_64b(input []byte, secret []byte, seed uint64) uint64 {
    len := len(input)

    acc := uint64(len) * PRIME64_1
    var acc_end uint64

    nbRounds := len / 16;
    var i int

    for i = 0; i < 8; i++ {
        acc += mix16B(input[16*i:], secret[16*i:], seed)
    }

    /* last bytes */
    acc_end = mix16B(input[len - 16:], secret[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET:], seed)

    acc = avalanche(acc)

    for i = 8; i < nbRounds; i++ {
        acc_end += mix16B(input[(16*i):], secret[(16*(i-8)) + MIDSIZE_STARTOFFSET:], seed)
    }

    return avalanche(acc + acc_end)
}

// =============

func len_1to3_128b(data []byte, secret []byte, seed uint64) Uint128 {
    c1 := data[0]
    c2 := data[len(data)>>1]
    c3 := data[len(data)-1]

    len := len(data)

    combinedl := (uint32(c1) << 16) |
                 (uint32(c2) << 24) |
                 (uint32(c3) <<  0) |
                 (uint32(len) << 8)
    combinedh := rotl32(swap32(combinedl), 13)

    bitflipl := uint64(getu32(secret[0:]) ^ getu32(secret[4:])) + seed
    bitfliph := uint64(getu32(secret[8:]) ^ getu32(secret[12:])) - seed

    keyed_lo := uint64(combinedl) ^ bitflipl
    keyed_hi := uint64(combinedh) ^ bitfliph

    var h128 Uint128
    h128.Low  = avalanche(keyed_lo)
    h128.High = avalanche(keyed_hi)

    return h128
}

func len_4to8_128b(input []byte, secret []byte, seed uint64) Uint128 {
    seed ^= uint64(swap32(uint32(seed))) << 32

    len := len(input)

    input_lo := getu32(input)
    input_hi := getu32(input[len - 4:])

    input_64 := uint64(input_lo) + (uint64(input_hi) << 32)
    bitflip  := getu64(secret[16:]) ^ getu64(secret[24:]) + seed
    keyed    := input_64 ^ bitflip

    /* Shift len to the left to ensure it is even, this avoids even multiplies. */
    m128 := mult64to128(keyed, uint64(PRIME64_1) + uint64(len << 2))

    m128.High += (m128.Low << 1)
    m128.Low  ^= (m128.High >> 3)

    m128.Low   = xorshift64(m128.Low, 35)
    m128.Low  *= PRIME_MX2
    m128.Low   = xorshift64(m128.Low, 28)
    m128.High  = avalanche(m128.High)

    return m128
}

func len_9to16_128b(input []byte, secret []byte, seed uint64) Uint128 {
    len := len(input)

    bitflipl := getu64(secret[32:]) ^ getu64(secret[40:]) - seed
    bitfliph := getu64(secret[48:]) ^ getu64(secret[56:]) + seed

    input_lo := getu64(input[0:])
    input_hi := getu64(input[len - 8:])

    m128 := mult64to128(input_lo ^ input_hi ^ bitflipl, uint64(PRIME64_1))

    m128.Low += uint64(len - 1) << 54
    input_hi ^= bitfliph

    m128.High += input_hi + mult32to64(uint32(input_hi), uint32(PRIME32_2) - 1)

    /* m128 ^= XXH_swap64(m128 >> 64); */
    m128.Low  ^= swap64(m128.High)

    /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
    h128 := mult64to128(m128.Low, PRIME64_2)
    h128.High += m128.High * PRIME64_2

    h128.Low   = avalanche(h128.Low)
    h128.High  = avalanche(h128.High)

    return h128
}

func len_0to16_128b(input []byte, secret []byte, seed uint64) Uint128 {
    len := len(input)

    if len > 8 {
        return len_9to16_128b(input, secret, seed)
    }
    if len >= 4 {
        return len_4to8_128b(input, secret, seed)
    }
    if len > 0 {
        return len_1to3_128b(input, secret, seed)
    }

    var h128 Uint128
    bitflipl := getu64(secret[64:]) ^ getu64(secret[72:])
    bitfliph := getu64(secret[80:]) ^ getu64(secret[88:])

    h128.Low  = avalanche(seed ^ bitflipl)
    h128.High = avalanche(seed ^ bitfliph)
    return h128
}

func mix32B(
    acc     Uint128,
    input_1 []byte,
    input_2 []byte,
    secret  []byte,
    seed    uint64,
) Uint128 {
    acc.Low  += mix16B(input_1, secret[0:], seed)
    acc.Low  ^= getu64(input_2) + getu64(input_2[8:])
    acc.High += mix16B(input_2, secret[16:], seed)
    acc.High ^= getu64(input_1) + getu64(input_1[8:])
    return acc
}

func len_17to128_128b(input []byte, secret []byte, seed uint64) Uint128 {
    len := len(input)

    var acc Uint128
    acc.Low = uint64(len) * uint64(PRIME64_1)
    acc.High = 0

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = mix32B(acc, input[48:], input[len-64:], secret[96:], seed)
            }

            acc = mix32B(acc, input[32:], input[len-48:], secret[64:], seed)
        }

        acc = mix32B(acc, input[16:], input[len-32:], secret[32:], seed)
    }

    acc = mix32B(acc, input, input[len-16:], secret, seed)

    var h128 Uint128
    h128.Low  = acc.Low + acc.High
    h128.High = (acc.Low    * uint64(PRIME64_1)) +
                (acc.High   * uint64(PRIME64_4)) +
                ((uint64(len) - seed) * uint64(PRIME64_2))
    h128.Low  = avalanche(h128.Low)
    h128.High = 0 - avalanche(h128.High)
    return h128
}

func len_129to240_128b(input []byte, secret []byte, seed uint64) Uint128 {
    var i int
    var acc Uint128

    len := len(input)

    acc.Low = uint64(len) * uint64(PRIME64_1)
    acc.High = 0

    for i = 32; i < 160; i += 32 {
        acc = mix32B(
                acc,
                input[i - 32:],
                input[i - 16:],
                secret[i - 32:],
                seed,
            )
    }

    acc.Low  = avalanche(acc.Low)
    acc.High = avalanche(acc.High)

    for i = 160; i <= len; i += 32 {
        acc = mix32B(
                acc,
                input[i - 32:],
                input[i - 16:],
                secret[MIDSIZE_STARTOFFSET + i - 160:],
                seed,
           )
    }

    /* last bytes */
    acc = mix32B(
            acc,
            input[len - 16:],
            input[len - 32:],
            secret[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET - 16:],
            0 - seed,
        )

    var h128 Uint128
    h128.Low  = acc.Low + acc.High
    h128.High = (acc.Low    * uint64(PRIME64_1)) +
                (acc.High   * uint64(PRIME64_4)) +
                ((uint64(len) - seed) * uint64(PRIME64_2))
    h128.Low  = avalanche(h128.Low)
    h128.High = 0 - avalanche(h128.High)
    return h128
}

func mergeAccs_128b(
    acc    []uint64,
    secret []byte,
    length uint64,
) Uint128 {
    var h128 Uint128
    h128.Low  = mergeAccs(
                     acc,
                     secret[SECRET_MERGEACCS_START:],
                     length * uint64(PRIME64_1),
                  )
    h128.High = mergeAccs(
                    acc,
                    secret[len(secret) - len(acc)*8 - SECRET_MERGEACCS_START:],
                    ^(length * uint64(PRIME64_2)),
                 )
    return h128
}

// =============

func GenCustomSecret(customSecret []byte, seed64 uint64) {
    kSecretPtr := kSecret
    nbRounds := SECRET_DEFAULT_SIZE / 16

    var i int
    for i = 0; i < nbRounds; i++ {
        lo := getu64(kSecretPtr[16*i:])     + seed64
        hi := getu64(kSecretPtr[16*i + 8:]) - seed64

        putu64(customSecret[16*i:],     lo)
        putu64(customSecret[16*i + 8:], hi)
    }
}

func hashLong_internal_loop(
    acc    []uint64,
    input  []byte,
    secret []byte,
) {
    secretSize := len(secret)
    length := len(input)

    nbStripesPerBlock := (secretSize - STRIPE_LEN) / SECRET_CONSUME_RATE
    block_len := STRIPE_LEN * nbStripesPerBlock
    nb_blocks := (length - 1) / block_len

    for n := 0; n < nb_blocks; n++ {
        accumulate(acc, input[n*block_len:], secret, nbStripesPerBlock)
        scrambleAcc(acc, secret[secretSize - STRIPE_LEN:])
    }

    /* last partial block */
    nbStripes := ((length - 1) - (block_len * nb_blocks)) / STRIPE_LEN
    accumulate(acc, input[nb_blocks*block_len:], secret, nbStripes)

    /* last stripe */
    if (length & (STRIPE_LEN - 1)) != 0 {
        p := input[length - STRIPE_LEN:]
        accumulate_512(acc, p, secret[secretSize - STRIPE_LEN - SECRET_LASTACC_START:])
    }
}

func consumeStripes(
    acc []uint64,
    nbStripesSoFarPtr *int,
    nbStripesPerBlock int,
    p []byte,
    stripes int,
    secret []byte,
    secretLimit int,
) {
    stripesSoFar := *nbStripesSoFarPtr
    if nbStripesPerBlock - stripesSoFar <= stripes {
        var stripesToEndOfBlock = nbStripesPerBlock - stripesSoFar
        var stripesAfterBlock   = stripes - stripesToEndOfBlock

        accumulate(acc, p, secret[stripesSoFar*SECRET_CONSUME_RATE:], stripesToEndOfBlock)
        scrambleAcc(acc, secret[secretLimit:])
        accumulate(acc, p[stripesToEndOfBlock*STRIPE_LEN:], secret, stripesAfterBlock)

        *nbStripesSoFarPtr = stripesAfterBlock
    } else {
        accumulate(acc, p, secret[stripesSoFar*SECRET_CONSUME_RATE:], stripes)

        *nbStripesSoFarPtr += stripes
    }
}

// =============

func Hash_hashLong_64bits_internal(
    acc    []uint64,
    input  []byte,
    secret []byte,
) uint64 {
    len := len(input)

    hashLong_internal_loop(acc, input, secret)

    return mergeAccs(acc, secret[SECRET_MERGEACCS_START:], uint64(len) * PRIME64_1)
}

func Hash_hashLong_64b_withSecret(
    input  []byte,
    seed64 uint64,
    secret []byte,
) uint64 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_hashLong_64bits_internal(acc, input, secret)
}

func Hash_64bits_internal(
    acc    []uint64,
    input  []byte,
    seed64 uint64,
    secret []byte,
) uint64 {
    len := len(input)

    if len <= 16 {
        return len_0to16_64b(input, secret, seed64)
    }

    if len <= 128 {
        return len_17to128_64b(input, secret, seed64)
    }

    if len <= MIDSIZE_MAX {
        return len_129to240_64b(input, secret, seed64)
    }

    return Hash_hashLong_64bits_internal(acc, input, secret)
}

func Hash_64bits(input []byte) uint64 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_64bits_internal(acc, input, 0, kSecret)
}

func Hash_64bits_withSecret(input []byte, secret []byte) uint64 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_64bits_internal(acc, input, 0, secret)
}

func Hash_64bits_withSeed(input []byte, seed uint64) uint64 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_64bits_internal(acc, input, seed, kSecret)
}

func Hash_64bits_withSecretandSeed(
    input  []byte,
    secret []byte,
    seed   uint64,
) uint64 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    length := len(input)
    if length <= MIDSIZE_MAX {
        return Hash_64bits_internal(acc, input, seed, kSecret)
    }

    return Hash_hashLong_64b_withSecret(input, seed, secret)
}

// =============

func Hash_hashLong_128b_internal(
    acc    []uint64,
    input  []byte,
    secret []byte,
) Uint128 {
    hashLong_internal_loop(acc, input, secret)

    return mergeAccs_128b(acc, secret, uint64(len(input)))
}

func Hash_hashLong_128b_default(
    input  []byte,
    seed64 uint64,
    secret []byte,
) Uint128 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_hashLong_128b_internal(acc, input, kSecret)
}

func Hash_hashLong_128b_withSecret(
    input  []byte,
    seed64 uint64,
    secret []byte,
) Uint128 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_hashLong_128b_internal(acc, input, secret)
}

func Hash_hashLong_128b_withSeed_internal(
    acc    []uint64,
    input  []byte,
    seed64 uint64,
) Uint128 {
    if seed64 == 0 {
        return Hash_hashLong_128b_internal(acc, input, kSecret)
    }

    var secret [SECRET_DEFAULT_SIZE]byte
    GenCustomSecret(secret[:], seed64)

    return Hash_hashLong_128b_internal(acc, input, secret[:])
}

func Hash_hashLong_128b_withSeed(
    input  []byte,
    seed64 uint64,
    secret []byte,
) Uint128 {
    acc := make([]uint64, 8)
    copy(acc, INIT_ACC)

    return Hash_hashLong_128b_withSeed_internal(acc, input, seed64)
}

type hashLong128_f func([]byte, uint64, []byte) Uint128

func Hash_128bits_internal(
    input  []byte,
    seed64 uint64,
    secret []byte,
    f_hl128 hashLong128_f,
) Uint128 {
    len := len(input)

    if len <= 16 {
        return len_0to16_128b(input, secret, seed64)
    }
    if len <= 128 {
        return len_17to128_128b(input, secret, seed64)
    }
    if len <= MIDSIZE_MAX {
        return len_129to240_128b(input, secret, seed64)
    }

    return f_hl128(input, seed64, secret)
}

func Hash_128bits(input []byte) Uint128 {
    return Hash_128bits_internal(input, 0, kSecret, Hash_hashLong_128b_default)
}

func Hash_128bits_withSecret(input []byte, secret []byte) Uint128 {
    return Hash_128bits_internal(input, 0, secret, Hash_hashLong_128b_withSecret)
}

func Hash_128bits_withSeed(input []byte, seed uint64) Uint128 {
    return Hash_128bits_internal(input, seed, kSecret, Hash_hashLong_128b_withSeed)
}

func Hash_128bits_withSecretandSeed(
    input  []byte,
    secret []byte,
    seed   uint64,
) Uint128 {
    len := len(input)
    if len <= MIDSIZE_MAX {
        return Hash_128bits_internal(input, seed, kSecret, nil)
    }

    return Hash_hashLong_128b_withSecret(input, seed, secret)
}
