package zuc

const KEY_SIZE = 16
const IV_SIZE  = 16
const MAC_SIZE = 4

type ZucMac struct {
    LFSR [16]uint32
    R1 uint32
    R2 uint32
    T uint32
    K0 uint32
    buf [4]byte
    buflen int
}

func NewZucMac(key []byte, iv []byte) *ZucMac {
    if l := len(key); l != 16 {
        panic(KeySizeError(l))
    }

    if l := len(iv); l != 16 {
        panic(IVSizeError(l))
    }

    m := new(ZucMac)
    m.init(key, iv)

    return m
}

func (this *ZucMac) Size() int {
    return MAC_SIZE
}

func (this *ZucMac) BlockSize() int {
    return IV_SIZE
}

func (this *ZucMac) Reset() {
    this.LFSR = [16]uint32{}
    this.T = 0
    this.buf = [4]byte{}
    this.buflen = 0
}

func (this *ZucMac) init(key []byte, iv []byte) {
    state := NewZucState(key, iv)

    this.LFSR = state.LFSR
    this.R1 = state.R1
    this.R2 = state.R2

    this.K0 = state.GenerateKeyword()
}

func (this *ZucMac) Write(data []byte) (nn int, err error) {
    var T uint32 = this.T
    var K0 uint32 = this.K0
    var K1, M uint32

    var R1 uint32 = this.R1
    var R2 uint32 = this.R2
    var X0, X1, X2, X3 uint32
    var i int

    nn = len(data)
    if nn == 0 {
        return
    }

    var dataLen int = len(data)

    if this.buflen > 0 {
        var num int = len(this.buf) - this.buflen

        if dataLen < num {
            copy(this.buf[this.buflen:], data)
            this.buflen += dataLen

            return
        }

        copy(this.buf[this.buflen:], data[:num])

        M = GETU32(this.buf[:])
        this.buflen = 0

        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        K1 = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])

        for i = 0; i < 32; i++ {
            if (M & 0x80000000) > 0 {
                T ^= K0
            }

            M <<= 1
            K0 = (K0 << 1) | (K1 >> 31)
            K1 <<= 1
        }

        data = data[num:]
        dataLen -= num
    }

    for dataLen >= 4 {
        M = GETU32(data)

        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        K1 = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])

        for i = 0; i < 32; i++ {
            if (M & 0x80000000) > 0 {
                T ^= K0
            }

            M <<= 1
            K0 = (K0 << 1) | (K1 >> 31)
            K1 <<= 1
        }

        data = data[4:]
        dataLen -= 4
    }

    if dataLen > 0 {
        copy(this.buf[:], data)
        this.buflen = dataLen
    }

    this.R1 = R1
    this.R2 = R2
    this.K0 = K0
    this.T = T

    return
}

func (this *ZucMac) Sum(data []byte, nbits int) []byte {
    var T uint32 = this.T;
    var K0 uint32 = this.K0;
    var K1, M uint32

    var R1 uint32 = this.R1;
    var R2 uint32 = this.R2;
    var X0, X1, X2, X3 uint32
    var i int

    var mac [4]byte

    if len(data) == 0 {
        nbits = 0;
    }

    if nbits >= 8 {
        this.Write(data[:nbits/8])

        data = data[nbits/8:]

        nbits %= 8
    }

    T = this.T
    K0 = this.K0
    R1 = this.R1
    R2 = this.R2

    if nbits > 0 {
        this.buf[this.buflen] = data[0]
    }

    if this.buflen > 0 || nbits > 0 {
        M = GETU32(this.buf[:])
        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        K1 = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])

        for i = 0; i < this.buflen * 8 + nbits; i++ {
            if (M & 0x80000000) > 0 {
                T ^= K0
            }

            M <<= 1
            K0 = (K0 << 1) | (K1 >> 31)
            K1 <<= 1
        }
    }

    T ^= K0

    BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
    K1 = X3 ^ F(&R1, &R2, X0, X1, X2)
    LFSRWithWorkMode(this.LFSR[:])
    T ^= K1

    this.T = T;
    PUTU32(mac[:], T)

    return mac[:]
}
