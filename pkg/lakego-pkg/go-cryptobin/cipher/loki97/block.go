package loki97

const (
    ROUNDS = 16
)

func blockDecrypt(in []byte, sessionKey []ULONG64) []byte {
    var SK []ULONG64 = sessionKey    // local ref to session key

    // pack input block into 2 longs: L and R
    L := byteToULONG64(in[:8])
    R := byteToULONG64(in[8:])

    // compute all rounds for this 1 block
    var nR, f_out ULONG64
    var k int16 = NUM_SUBKEYS - 1
    var i int16

    for i = 0; i < ROUNDS; i++ {
        nR = sub64(R, SK[k])
        k--

        f_out = compute(nR, SK[k])
        k--

        nR = sub64(nR, SK[k])
        k--

        R.l = L.l ^ f_out.l
        R.r = L.r ^ f_out.r

        L = nR
    }

    // unpack resulting L & R into out buffer
    var result []byte

    RBytes := ULONG64ToBYTE(R)
    LBytes := ULONG64ToBYTE(L)

    result = append(result, RBytes[:]...)
    result = append(result, LBytes[:]...)

    return result
}

func blockEncrypt(in []byte, sessionKey []ULONG64) []byte {
    var SK []ULONG64 = sessionKey    // local ref to session key

    // pack input block into 2 longs: L and R
    L := byteToULONG64(in[:8])
    R := byteToULONG64(in[8:])

    // compute all rounds for this 1 block
    var nR, f_out ULONG64
    var k int16 = 0
    var i int16

    for i = 0; i < ROUNDS; i++ {
        nR = add64(R, SK[k])
        k++

        f_out = compute(nR, SK[k])
        k++

        nR = add64(nR, SK[k])
        k++

        R.l = L.l ^ f_out.l
        R.r = L.r ^ f_out.r

        L = nR
    }

    // unpack resulting L & R into out buffer
    var result []byte

    RBytes := ULONG64ToBYTE(R)
    LBytes := ULONG64ToBYTE(L)

    result = append(result, RBytes[:]...)
    result = append(result, LBytes[:]...)

    return result
}
