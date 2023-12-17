package zuc

func (this *ZucState) SetEeaKey(userKey []byte, count uint32, bearer uint32, direction uint32) {
    iv := [16]byte{}

    iv[0] = byte(count >> 24)
    iv[8] = iv[0]
    iv[1] = byte(count >> 16)
    iv[9] = iv[1]
    iv[2] = byte(count >> 8)
    iv[10] = iv[2]
    iv[3] = byte(count)
    iv[11] = iv[3]
    iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
    iv[12] = iv[4]

    this.init(userKey, iv[:])
}

func EeaEncrypt(
    in []uint32,
    out []uint32,
    nbits int,
    key []byte,
    count uint32,
    bearer uint32,
    direction uint32,
) {
    var nwords int = (nbits + 31)/32
    var i int

    zucKey := &ZucState{}
    zucKey.SetEeaKey(key, count, bearer, direction)
    zucKey.GenerateKeystream(nwords, out)

    for i = 0; i < nwords; i++ {
        out[i] ^= in[i]
    }

    if nbits % 32 != 0 {
        out[nwords - 1] &= (0xffffffff << (32 - (nbits%32)))
    }
}

func SetEiaIV(
    iv []byte,
    count uint32,
    bearer uint32,
    direction uint32,
) {
    MemsetByte(iv, 0)

    iv[0] = byte(count >> 24)
    iv[1] = byte(count >> 16)
    iv[9] = iv[1]
    iv[2] = byte(count >> 8)
    iv[10] = iv[2]
    iv[3] = byte(count)
    iv[11] = iv[3]
    iv[4] = byte(bearer << 3)
    iv[12] = iv[4]
    iv[8] = byte(uint32(iv[0]) ^ (direction << 7))
    iv[14] = byte(direction << 7)
}

func EiaGenerateMac(
    data []uint32,
    nbits int,
    key [16]byte,
    count uint32,
    bearer uint32,
    direction uint32,
) uint32 {
    var ctx *ZucMac
    var iv [16]byte
    var mac []byte

    SetEiaIV(iv[:], count, bearer, direction)

    ctx = NewZucMac(key[:], iv[:])

    dataBytes := uint32sToBytes(data)
    mac = ctx.Sum(dataBytes, nbits)

    return GETU32(mac)
}

const ZUC_BLOCK_SIZE = 4

type Zuc struct{
    zuc_state *ZucState
    block [4]byte
    block_nbytes int
}

func newZuc(key []byte, iv []byte) *Zuc {
    z := new(Zuc)
    z.init(key, iv)

    return z
}

func NewZucEncrypt(key []byte, iv []byte) *Zuc {
    return newZuc(key, iv)
}

func NewZucDecrypt(key []byte, iv []byte) *Zuc {
    return newZuc(key, iv)
}

func (this *Zuc) init(key []byte, iv []byte) {
    this.zuc_state = NewZucState(key, iv)

    this.block = [4]byte{}
    this.block_nbytes = 0
}

func (this *Zuc) Write(in []byte, out []byte) (nn int, err error) {
    var left int
    var nblocks int
    var dataLen int

    var inlen int = len(in)

    if this.block_nbytes >= ZUC_BLOCK_SIZE {
        panic("block nbytes error")
    }

    nn = len(in)

    var outlen int = 0

    if this.block_nbytes > 0 {
        left = ZUC_BLOCK_SIZE - this.block_nbytes;
        if inlen < left {
            copy(this.block[this.block_nbytes:], in)
            this.block_nbytes += inlen

            return
        }

        copy(this.block[this.block_nbytes:], in[:left])

        this.zuc_state.Encrypt(out, this.block[:ZUC_BLOCK_SIZE])

        in = in[left:]
        inlen -= left

        out = out[ZUC_BLOCK_SIZE:]
        outlen += ZUC_BLOCK_SIZE
    }

    if inlen >= ZUC_BLOCK_SIZE {
        nblocks = inlen / ZUC_BLOCK_SIZE
        dataLen = nblocks * ZUC_BLOCK_SIZE

        this.zuc_state.Encrypt(out, in[:dataLen])

        in = in[dataLen:]
        inlen -= dataLen;

        out = out[dataLen:]
        outlen += dataLen
    }

    if inlen > 0 {
        copy(this.block[:], in)
    }

    this.block_nbytes = inlen

    return
}

func (this *Zuc) Sum(data []byte) []byte {
    if this.block_nbytes >= ZUC_BLOCK_SIZE {
        panic("block nbytes error")
    }

    var out []byte = make([]byte, this.block_nbytes)

    this.zuc_state.Encrypt(out, this.block[:this.block_nbytes])

    return append(data, out...)
}
