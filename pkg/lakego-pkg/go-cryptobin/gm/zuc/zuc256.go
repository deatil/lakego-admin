package zuc

var ZUC256_D = [][]uint8{
    {
        0x22,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
        0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
    },
    {
        0x22,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
        0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
    },
    {
        0x23,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
        0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
    },
    {
        0x23,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
        0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
    },
};

func ZUC256_MAKEU31(a, b, c, d byte) uint32 {
    return uint32(a) << 23 |
           uint32(b) << 16 |
           uint32(c) <<  8 |
           uint32(d)
}

type Zuc256State struct {
    LFSR [16]uint32
    R1 uint32
    R2 uint32
}

func NewZuc256State(key []byte, iv []byte) *Zuc256State {
    if l := len(key); l != 32 {
        panic(KeySizeError(l))
    }

    if l := len(iv); l != 23 {
        panic(IVSizeError(l))
    }

    s := new(Zuc256State)
    s.init(key, iv)

    return s
}

func NewZuc256StateWithMacbits(key []byte, iv []byte, macbits int32) *Zuc256State {
    if l := len(key); l != 32 {
        panic(KeySizeError(l))
    }

    if l := len(iv); l != 23 {
        panic(IVSizeError(l))
    }

    s := new(Zuc256State)
    s.setMacKey(key, iv, macbits)

    return s
}

func (this *Zuc256State) setMacKey(K []byte, IV []byte, macbits int32) {
    var R1, R2 uint32
    var X0, X1, X2 uint32
    var W uint32

    var D []byte
    var i int32

    var IV17 uint8 = IV[17] >> 2
    var IV18 uint8 = ((IV[17] & 0x3) << 4) | (IV[18] >> 4)
    var IV19 uint8 = ((IV[18] & 0xf) << 2) | (IV[19] >> 6)
    var IV20 uint8 = IV[19] & 0x3f
    var IV21 uint8 = IV[20] >> 2
    var IV22 uint8 = ((IV[20] & 0x3) << 4) | (IV[21] >> 4)
    var IV23 uint8 = ((IV[21] & 0xf) << 2) | (IV[22] >> 6)
    var IV24 uint8 = IV[22] & 0x3f

    if macbits/32 < 3 {
        D = ZUC256_D[macbits/32]
    } else {
        D = ZUC256_D[3]
    }

    this.LFSR[0] = ZUC256_MAKEU31(K[0], D[0], K[21], K[16])
    this.LFSR[1] = ZUC256_MAKEU31(K[1], D[1], K[22], K[17])
    this.LFSR[2] = ZUC256_MAKEU31(K[2], D[2], K[23], K[18])
    this.LFSR[3] = ZUC256_MAKEU31(K[3], D[3], K[24], K[19])
    this.LFSR[4] = ZUC256_MAKEU31(K[4], D[4], K[25], K[20])
    this.LFSR[5] = ZUC256_MAKEU31(IV[0], (D[5] | IV17), K[5], K[26])
    this.LFSR[6] = ZUC256_MAKEU31(IV[1], (D[6] | IV18), K[6], K[27])
    this.LFSR[7] = ZUC256_MAKEU31(IV[10], (D[7] | IV19), K[7], IV[2])
    this.LFSR[8] = ZUC256_MAKEU31(K[8], (D[8] | IV20), IV[3], IV[11])
    this.LFSR[9] = ZUC256_MAKEU31(K[9], (D[9] | IV21), IV[12], IV[4])
    this.LFSR[10] = ZUC256_MAKEU31(IV[5], (D[10] | IV22), K[10], K[28])
    this.LFSR[11] = ZUC256_MAKEU31(K[11], (D[11] | IV23), IV[6], IV[13])
    this.LFSR[12] = ZUC256_MAKEU31(K[12], (D[12] | IV24), IV[7], IV[14])
    this.LFSR[13] = ZUC256_MAKEU31(K[13], D[13], IV[15], IV[8])
    this.LFSR[14] = ZUC256_MAKEU31(K[14], (D[14] | (K[31] >> 4)), IV[16], IV[9])
    this.LFSR[15] = ZUC256_MAKEU31(K[15], (D[15] | (K[31] & 0x0F)), K[30], K[29])

    R1 = 0
    R2 = 0

    for i = 0; i < 32; i++ {
        BitReconstruction3(&X0, &X1, &X2, this.LFSR[:])
        W = F(&R1, &R2, X0, X1, X2)
        LFSRWithInitialisationMode(W >> 1, this.LFSR[:])
    }

    BitReconstruction2(&X1, &X2, this.LFSR[:])
    F_(&R1, &R2, X1, X2)
    LFSRWithWorkMode(this.LFSR[:])

    this.R1 = R1
    this.R2 = R2
}

func (this *Zuc256State) init(key []byte, iv []byte) {
    this.setMacKey(key, iv, 0)
}

func (this *Zuc256State) GenerateKeyword() uint32 {
    s := (*ZucState)(this)

    z := s.GenerateKeyword()

    this = (*Zuc256State)(s)

    return z
}

func (this *Zuc256State) GenerateKeystream(nwords int, keystream []uint32) {
    s := (*ZucState)(this)

    s.GenerateKeystream(nwords, keystream)

    this = (*Zuc256State)(s)
}

func (this *Zuc256State) Encrypt(out []byte, in []byte) {
    s := (*ZucState)(this)

    s.Encrypt(out, in)

    this = (*Zuc256State)(s)
}
