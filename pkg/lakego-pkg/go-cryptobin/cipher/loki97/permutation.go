package loki97

// 256
const PERMUTATION_SIZE = 0x100

func permutationGeneration() [PERMUTATION_SIZE]ULONG64 {
    var P [PERMUTATION_SIZE]ULONG64

    var pval uint32
    var i uint32

    var j, k uint32

    /*  initialising expanded permutation P table (for lowest BYTE only) */
    /*    Permutation P maps input bits [63..0] to outputs bits: */
    /*    [56, 48, 40, 32, 24, 16,  8, 0, */
    /*     57, 49, 41, 33, 25, 17,  9, 1, */
    /*     58, 50, 42, 34, 26, 18, 10, 2, */
    /*     59, 51, 43, 35, 27, 19, 11, 3, */
    /*     60, 52, 44, 36, 28, 20, 12, 4, */
    /*     61, 53, 45, 37, 29, 21, 13, 5, */
    /*     62, 54, 46, 38, 30, 22, 14, 6, */
    /*     63, 55, 47, 39, 31, 23, 15, 7]  <- this row only used in table */
    /*   since it is so regular, we can construct it on the fly */
    for i = 0; i < PERMUTATION_SIZE; i++ { /*  loop over all 8-bit inputs */
        /*  for each input bit permute to specified output position */
        /* do right half of P */
        pval = 0
        for j, k = 0, 7; j < 4; j, k = j+1, k+8 {
            pval |= uint32(((i >> j) & 0x1)) << k
        }
        P[i].r = pval

        /* do left half of P */
        pval = 0
        for j, k = 4, 7; j < 8; j, k = j+1, k+8 {
            pval |= uint32(((i >> j) & 0x1)) << k
        }
        P[i].l = pval
    }

    return P
}
