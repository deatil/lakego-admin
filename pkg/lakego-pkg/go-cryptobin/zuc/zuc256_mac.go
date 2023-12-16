package zuc

const ZUC256_KEY_SIZE     = 32
const ZUC256_IV_SIZE      = 23
const ZUC256_MAC32_SIZE   = 4
const ZUC256_MAC64_SIZE   = 8
const ZUC256_MAC128_SIZE  = 16
const ZUC256_MIN_MAC_SIZE = ZUC256_MAC32_SIZE
const ZUC256_MAX_MAC_SIZE = ZUC256_MAC128_SIZE

type Zuc256Mac struct {
    LFSR [16]uint32
    R1 uint32
    R2 uint32
    T [4]uint32
    K0 [4]uint32
    buf [4]byte
    buflen int
    macbits int32
}

func (this *Zuc256Mac) Size() int {
    return int(this.macbits / 8)
}

func (this *Zuc256Mac) BlockSize() int {
    return ZUC256_IV_SIZE
}

func (this *Zuc256Mac) Reset() {
    this.LFSR = [16]uint32{}
    this.T = [4]uint32{}
    this.buf = [4]byte{}
    this.buflen = 0
}

// key = 32
// iv = 23
func (this *Zuc256Mac) init(key []byte, iv []byte, macbits int32) {
    if macbits < 32 {
        macbits = 32
    } else if macbits > 64 {
        macbits = 128
    }

    state := NewZuc256StateWithMacbits(key, iv, macbits)

    state.GenerateKeystream(int(macbits/32), this.T[:])
    state.GenerateKeystream(int(macbits/32), this.K0[:])

    this.LFSR = state.LFSR
    this.R1 = state.R1
    this.R2 = state.R2

    this.macbits = (macbits/32) * 32
}

func (this *Zuc256Mac) generateKeyword() uint32 {
    ss := Zuc256State{
        LFSR: this.LFSR,
        R1: this.R1,
        R2: this.R2,
    }

    K1 := ss.GenerateKeyword()

    this.LFSR = ss.LFSR
    this.R1 = ss.R1
    this.R2 = ss.R2

    return K1
}

func (this *Zuc256Mac) Write(data []byte) (nn int, err error) {
    var K1, M uint32
    var n int = int(this.macbits / 32)
    var i, j int

    nn = len(data)
    if nn == 0 {
        return
    }

    var dataLen int = len(data)

    if this.buflen > 0 {
        var num int = len(this.buf) - this.buflen
        if (dataLen < num) {
            copy(this.buf[this.buflen:], data)
            this.buflen += dataLen

            return
        }

        copy(this.buf[this.buflen:], data[:num])
        M = GETU32(this.buf[:])
        this.buflen = 0

        K1 = this.generateKeyword()

        for i = 0; i < 32; i++ {
            if (M & 0x80000000) > 0 {
                for j = 0; j < n; j++ {
                    this.T[j] ^= this.K0[j]
                }
            }

            M <<= 1
            for j = 0; j < n - 1; j++ {
                this.K0[j] = (this.K0[j] << 1) | (this.K0[j + 1] >> 31)
            }

            this.K0[j] = (this.K0[j] << 1) | (K1 >> 31)
            K1 <<= 1
        }

        data = data[num:]
        dataLen -= num
    }

    for dataLen >= 4 {
        M = GETU32(data)

        K1 = this.generateKeyword()

        for i = 0; i < 32; i++ {
            if (M & 0x80000000) > 0 {
                for j = 0; j < n; j++ {
                    this.T[j] ^= this.K0[j]
                }
            }

            M <<= 1
            for j = 0; j < n - 1; j++ {
                this.K0[j] = (this.K0[j] << 1) | (this.K0[j + 1] >> 31)
            }

            this.K0[j] = (this.K0[j] << 1) | (K1 >> 31)
            K1 <<= 1
        }

        data = data[4:]
        dataLen -= 4
    }

    if dataLen > 0 {
        copy(this.buf[:], data)
        this.buflen = dataLen
    }

    return
}

func (this *Zuc256Mac) Sum(data []byte) []byte {
    var K1, M uint32
    var n int = int(this.macbits/32)
    var i, j int

    var mac []byte = make([]byte, n * 4)

    nbits := len(data) * 8

    if len(data) == 0 {
        nbits = 0
    }

    if nbits >= 8 {
        this.Write(data[:nbits/8])
        data = data[nbits/8:]
        nbits %= 8
    }

    if nbits > 0 {
        copy(this.buf[this.buflen:], data)
    }

    if this.buflen > 0 || nbits > 0 {
        M = GETU32(this.buf[:])

        K1 = this.generateKeyword()

        for i = 0; i < this.buflen * 8 + nbits; i++ {
            if (M & 0x80000000) > 0 {
                for j = 0; j < n; j++ {
                    this.T[j] ^= this.K0[j]
                }
            }

            M <<= 1
            for j = 0; j < n - 1; j++ {
                this.K0[j] = (this.K0[j] << 1) | (this.K0[j + 1] >> 31)
            }

            this.K0[j] = (this.K0[j] << 1) | (K1 >> 31)
            K1 <<= 1
        }
    }

    for j = 0; j < n; j++ {
        this.T[j] ^= this.K0[j]
        PUTU32(mac, this.T[j])
        mac = mac[4:]
    }

    return mac
}
