package whirlx

import (
    "math/bits"
)

func add(x, y byte) byte {
    return x + y
}

func sub(x, y byte) byte {
    return x - y
}

func rotl(x byte, n int) byte {
    return bits.RotateLeft8(x, n)
}

func rotr(x byte, n int) byte {
    return bits.RotateLeft8(x, -n)
}

/*
func confuse(x byte) byte   {
    return rotl(x^0xA5, 3)
}

func deconfuse(x byte) byte {
    return rotr(x, 3) ^ 0xA5
}
*/

func confuse(x byte) byte {
    x ^= 0xA5        // 1. XOR
    x = add(x, 0x3C) // 2. ADD
    x = rotl(x, 3)   // 3. ROTATE LEFT
    return x
}

func deconfuse(x byte) byte {
    x = rotr(x, 3)   // 1. ROTATE RIGHT (inverse of rotl)
    x = sub(x, 0x3C) // 2. SUB (inverse of add)
    x ^= 0xA5        // 3. XOR (same as XOR inverse)
    return x
}

func confuseN(x byte, n int) byte {
    for i := 0; i < n; i++ {
        x = confuse(x)
    }
    return x
}

func deconfuseN(x byte, n int) byte {
    for i := 0; i < n; i++ {
        x = deconfuse(x)
    }
    return x
}

func mixState(state []byte) {
    for i := 0; i < len(state); i++ {
        state[i] = rotl(state[i]^state[(i+1)%len(state)], 3)
    }
}

func invMixState(state []byte) {
    for i := len(state) - 1; i >= 0; i-- {
        state[i] = rotr(state[i], 3) ^ state[(i+1)%len(state)]
    }
}

func round(x, k byte, r int) byte {
    x = add(x, k)
    x = confuseN(x, 4) // mais confusão!
    x = rotl(x, (r+3)%8)
    x ^= k
    x = rotl(x, (r+5)%8)
    return x
}

func invRound(x, k byte, r int) byte {
    x = rotr(x, (r+5)%8)
    x ^= k
    x = rotr(x, (r+3)%8)
    x = deconfuseN(x, 4)
    x = sub(x, k)
    return x
}

func subKey(k []byte, round, i int) byte {
    base := k[(i+round)%len(k)]
    base = rotl(base^byte(i*73+round*91), (round+i)%8)
    return base
}

