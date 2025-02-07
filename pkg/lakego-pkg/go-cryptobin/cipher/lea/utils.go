package lea

import (
    "math/bits"
    "encoding/binary"
)

var delta = [8]uint32{
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
}

func rol(x uint32, n uint) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func ror(x uint32, n uint) uint32 {
    return rol(x, 32 - n)
}

func ba2w(inp [4]byte) uint32 {
    return binary.LittleEndian.Uint32(inp[0:])
}

func w2ba(inp uint32) [4]byte {
    var sav [4]byte

    binary.LittleEndian.PutUint32(sav[0:], inp)

    return sav
}

// roundKey returns round keys for encryption or decryption
// param K is a key (128-bit, 192-bit, or 256-bit)
// # of rows of return value (RK) will be different by the given key size
func roundKey(K []byte, isEncrypt bool) (RK [][6]uint32) {
    var Nr uint
    switch len(K) {
        case 16:
            Nr = 24
        case 24:
            Nr = 28
        case 32:
            Nr = 32
    }

    T := make([]uint32, len(K)/4)
    RK = make([][6]uint32, Nr)
    for i := 0; i < len(K)/4; i++ {
        var buf [4]byte
        copy(buf[:], K[i*4:(i+1)*4])
        T[i] = ba2w(buf)
    }

    for i := uint(0); i < Nr; i++ {
        var rki uint
        // procedures for generating round keys for encryption and decryption are the same
        // when decrypting mode, save them in reverse
        switch isEncrypt {
            case true:
                rki = i
            case false:
                rki = Nr - i - 1
        }

        switch len(K) {
            case 16:
                T[0] = rol(T[0]+rol(delta[i%4], i), 1)
                T[1] = rol(T[1]+rol(delta[i%4], i+1), 3)
                T[2] = rol(T[2]+rol(delta[i%4], i+2), 6)
                T[3] = rol(T[3]+rol(delta[i%4], i+3), 11)
                RK[rki] = [6]uint32{T[0], T[1], T[2], T[1], T[3], T[1]}
            case 24:
                T[0] = rol(T[0]+rol(delta[i%6], i), 1)
                T[1] = rol(T[1]+rol(delta[i%6], i+1), 3)
                T[2] = rol(T[2]+rol(delta[i%6], i+2), 6)
                T[3] = rol(T[3]+rol(delta[i%6], i+3), 11)
                T[4] = rol(T[4]+rol(delta[i%6], i+4), 13)
                T[5] = rol(T[5]+rol(delta[i%6], i+5), 17)
                RK[rki] = [6]uint32{T[0], T[1], T[2], T[3], T[4], T[5]}
            case 32:
                T[(6*i)%8] = rol(T[(6*i)%8]+rol(delta[i%8], i), 1)
                T[(6*i+1)%8] = rol(T[(6*i+1)%8]+rol(delta[i%8], i+1), 3)
                T[(6*i+2)%8] = rol(T[(6*i+2)%8]+rol(delta[i%8], i+2), 6)
                T[(6*i+3)%8] = rol(T[(6*i+3)%8]+rol(delta[i%8], i+3), 11)
                T[(6*i+4)%8] = rol(T[(6*i+4)%8]+rol(delta[i%8], i+4), 13)
                T[(6*i+5)%8] = rol(T[(6*i+5)%8]+rol(delta[i%8], i+5), 17)
                RK[rki] = [6]uint32{T[(6*i)%8], T[(6*i+1)%8], T[(6*i+2)%8], T[(6*i+3)%8], T[(6*i+4)%8], T[(6*i+5)%8]}
        }
    }

    return
}

// encRound is one round for encryption
func encRound(x [4]uint32, rk [6]uint32) (t [4]uint32) {
    t[0] = rol((x[0]^rk[0])+(x[1]^rk[1]), 9)
    t[1] = ror((x[1]^rk[2])+(x[2]^rk[3]), 5)
    t[2] = ror((x[2]^rk[4])+(x[3]^rk[5]), 3)
    t[3] = x[0]
    return
}

// decRound is one round for decryption
func decRound(x [4]uint32, rk [6]uint32) (t [4]uint32) {
    t[0] = x[3]
    t[1] = (ror(x[0], 9) - (t[0] ^ rk[0])) ^ rk[1]
    t[2] = (rol(x[1], 5) - (t[1] ^ rk[2])) ^ rk[3]
    t[3] = (rol(x[2], 3) - (t[2] ^ rk[4])) ^ rk[5]
    return
}

// helper function for encryption and decryption
// LEA uses 4 words (4 bytes * 4 = 16 bytes = 128 bits) for encryption or decryption
// 1. breaks the given 16 bytes into 4 words
// 2. encrypts or decrypts them
// 3. reconstructs 4 words to 16 bytes
func crypt(from []byte, RK [][6]uint32, isEncrypt bool) (to [16]byte) {
    var X [4]uint32
    for i := 0; i < 4; i++ {
        var buf [4]byte
        copy(buf[:], from[i*4:(i+1)*4])
        X[i] = ba2w(buf)
    }

    Nr := len(RK)
    for i := 0; i < Nr; i++ {
        switch isEncrypt {
            case true:
                X = encRound(X, RK[i])
            case false:
                X = decRound(X, RK[i])
        }
    }

    for i := 0; i < 4; i++ {
        buf := w2ba(X[i])
        copy(to[i*4:(i+1)*4], buf[:])
    }

    return
}
