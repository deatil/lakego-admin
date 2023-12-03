package seed

func g(n uint32) uint32 {
    return ss0[0xFF&(n>>0)] ^ ss1[0xFF&(n>>8)] ^ ss2[0xFF&(n>>16)] ^ ss3[0xFF&(n>>24)]
}

func processBlock(t0, t1 uint32) (uint32, uint32) {
    t1 ^= t0
    t1 = g(t1)
    t0 += t1
    t0 = g(t0)
    t1 += t0
    t1 = g(t1)
    t0 += t1

    return t0, t1
}
