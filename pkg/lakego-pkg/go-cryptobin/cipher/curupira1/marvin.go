package curupira1

type MAC interface {
    Init()
    InitWithR(R []byte)
    Update(aData []byte)
    GetTag(tag []byte, tagBits int) []byte
}

const c byte = 0x2A

type Marvin struct {
    cipher BlockCipher
    blockBytes int
    mLength int
    R []byte
    O []byte
    buffer []byte
    letterSoupMode bool
}

func NewMarvin(cipher BlockCipher, R []byte, letterSoupMode bool) MAC {
    m := new(Marvin)
    m.letterSoupMode = letterSoupMode
    m.cipher = cipher
    m.blockBytes = cipher.BlockSize()

    if R != nil {
        m.InitWithR(R)
    } else {
        m.Init()
    }

    return m
}

func (this *Marvin) Init() {
    blockBytes := this.blockBytes

    this.buffer = make([]byte, blockBytes)
    this.R = make([]byte, blockBytes)
    this.O = make([]byte, blockBytes)

    // Step 2 of Algorithm 1 - Page 4
    leftPaddedC := make([]byte, blockBytes)

    leftPaddedC[blockBytes - 1] = c
    this.cipher.Encrypt(this.R, leftPaddedC)

    xor(this.R, leftPaddedC)
    copy(this.O, this.R[0:blockBytes])
}

func (this *Marvin) InitWithR(R []byte) {
    blockBytes := this.blockBytes

    this.buffer = make([]byte, blockBytes)
    this.R = make([]byte, blockBytes)
    this.O = make([]byte, blockBytes)

    copy(this.R, R[0:blockBytes])
    copy(this.O, R[0:blockBytes])
}

func (this *Marvin) Update(aData []byte) {
    aLength := len(aData)
    blockBytes := this.blockBytes

    M := make([]byte, blockBytes)
    A := make([]byte, blockBytes)

    q := aLength / blockBytes
    r := aLength % blockBytes

    // Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
    xor(this.buffer, this.R)

    for i := 0; i < q; i++ {
        copy(M[0:], aData[i * blockBytes:])
        this.updateOffset()
        xor(M, this.O)
        this.cipher.Sct(A, M)
        xor(this.buffer, A)
    }

    if r != 0 {
        copy(M[0:], aData[q * blockBytes:q * blockBytes+r])

        for i := r; i < blockBytes; i++ {
            M[i] = 0
        }

        this.updateOffset()
        xor(M, this.O);
        this.cipher.Sct(A, M)
        xor(this.buffer, A)
    }

    this.mLength = aLength
}

func (this *Marvin) GetTag(tag []byte, tagBits int) []byte {
    if tag == nil {
        tag = make([]byte, tagBits / 8)
    }

    blockBytes := this.blockBytes

    if this.letterSoupMode {
        copy(tag[0:], this.buffer[0:blockBytes])
        return tag
    }

    // Steps 6-9 of Algorithm 1 - Page 4
    A := make([]byte, blockBytes)
    encryptedA := make([]byte, blockBytes)
    auxValue1 := make([]byte, blockBytes)
    auxValue2 := make([]byte, blockBytes)

    // auxValue1 = rpad(bin(n-tagBits)||1)
    diff := int8(this.cipher.BlockSize() * 8 - tagBits)
    if diff == 0 {
        auxValue1[0] = byte(0x80)
        auxValue1[1] = byte(0x00)
    } else if diff < 0 {
        auxValue1[0] = byte(diff)
        auxValue1[1] = byte(0x80)
    } else {
        diff = int8(diff << 1) | int8(0x01)
        for diff > 0 {
            diff = int8(diff << 1)
        }

        auxValue1[0] = byte(diff)
        auxValue1[1] = byte(0x00)
    }

    // auxValue2 = lpad(bin(|M|))
    processedBits := 8 * this.mLength
    for i := 0; i < 4; i++ {
        auxValue2[blockBytes - i - 1] = byte(processedBits >> (8 * i))
    }

    copy(A[0:], this.buffer[0:blockBytes])

    xor(A, auxValue1)
    xor(A, auxValue2)
    this.cipher.Encrypt(encryptedA, A)

    for i := 0; i < tagBits / 8; i++ {
        tag[i] = encryptedA[i]
    }

    return tag
}

func (this *Marvin) updateOffset() {
    // Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
    var O0 byte = this.O[0]

    copy(this.O[0:], this.O[1:12])

    this.O[9] = byte(this.O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
    this.O[10] = byte(this.O[10] ^ (O0 << 5) ^ (O0 << 3))
    this.O[11] = O0
}

