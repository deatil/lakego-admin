package curupira1

type AEAD interface {
    SetIV(iv []byte)
    Update(aData []byte)
    Encrypt(mData, cData []byte)
    Decrypt(cData, mData []byte)
    GetTag(tag []byte, tagBits int) []byte
}

type LetterSoup struct {
    mac MAC
    cipher BlockCipher
    blockBytes int
    mLength int
    hLength int
    iv []byte
    A []byte
    D []byte
    R []byte
    L []byte
}

func NewLetterSoup(cipher BlockCipher) AEAD {
    mac := NewMarvin(cipher, nil, true)
    return NewLetterSoupWithMAC(cipher, mac)
}

func NewLetterSoupWithMAC(cipher BlockCipher, mac MAC) AEAD {
    l := new(LetterSoup)
    l.cipher = cipher
    l.blockBytes = cipher.BlockSize()
    l.mac = mac

    return l
}

func (this *LetterSoup) SetIV(iv []byte) {
    ivLength := len(iv)
    blockBytes := this.blockBytes

    this.iv = make([]byte, ivLength)
    copy(this.iv, iv[:ivLength])

    this.L = []byte{}

    // Step 2 of Algorithm 2 - Page 6
    this.R = make([]byte, blockBytes)
    leftPaddedN := make([]byte, blockBytes)

    copy(leftPaddedN[blockBytes - ivLength:], iv[:blockBytes])
    this.cipher.Encrypt(this.R, leftPaddedN)
    xor(this.R, leftPaddedN)
}

func (this *LetterSoup) Update(aData []byte) {
    aLength := len(aData)
    blockBytes := this.blockBytes

    // Step 4 of Algorithm 2 - Page 6 (L and part of D)
    this.L = make([]byte, blockBytes)
    this.D = make([]byte, blockBytes)

    empty := make([]byte, blockBytes)

    this.hLength = aLength
    this.cipher.Encrypt(this.L, empty)

    this.mac.InitWithR(this.L)
    this.mac.Update(aData)
    this.mac.GetTag(this.D, this.cipher.BlockSize()*8)
}

func (this *LetterSoup) Encrypt(dst, src []byte) {
    mLength := len(src)
    blockBytes := this.blockBytes

    // Step 3 of Algorithm 2 - Page 6 (C and part of A)
    this.A = make([]byte, blockBytes)
    this.mLength = mLength

    if dst == nil {
        dst = make([]byte, blockBytes)
    }

    this.LFSRC(src, dst)

    this.mac.InitWithR(this.R)
    this.mac.Update(dst)
    this.mac.GetTag(this.A, this.cipher.BlockSize()*8)
}

func (this *LetterSoup) Decrypt(dst, src []byte) {
    this.LFSRC(src, dst)
}

func (this *LetterSoup) GetTag(tag []byte, tagBits int) []byte {
    if tag == nil {
        tag = make([]byte, tagBits / 8)
    }

    blockBytes := this.blockBytes

    // Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
    Atemp := make([]byte, blockBytes)
    copy(Atemp[0:], this.A[0:blockBytes])
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
    for i := 0; i < 4; i++ {
        auxValue2[blockBytes - i - 1] = byte((this.mLength * 8) >> (8 * i))
    }

    copy(this.A[0:], Atemp[0:blockBytes])
    xor(Atemp, auxValue1)
    xor(Atemp, auxValue2)

    // Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
    if len(this.L) != 0 {
        // auxValue2 = lpad(bin(|H|))
        auxValue2 := make([]byte, blockBytes)

        for i := 0; i < 4; i++ {
            auxValue2[blockBytes - i - 1] = byte((this.hLength * 8) >> (8 * i))
        }

        Dtemp := make([]byte, blockBytes)
        copy(Dtemp[0:], this.D[0:blockBytes])

        xor(Dtemp, auxValue1)
        xor(Dtemp, auxValue2)
        this.cipher.Sct(auxValue1, Dtemp)
        xor(Atemp, auxValue1)
    }

    // Step 7 of Algorithm 2 - Page 6
    this.cipher.Encrypt(auxValue1, Atemp)

    for i := 0; i < tagBits / 8; i++ {
        tag[i] = auxValue1[i]
    }

    return tag
}

func (this *LetterSoup) LFSRC(mData, cData []byte) {
    mLength := len(mData)
    blockBytes := this.blockBytes

    // Algorithm 8 - Page 20
    M := make([]byte, blockBytes)
    C := make([]byte, blockBytes)
    O := make([]byte, blockBytes)
    copy(O[0:], this.R[0:blockBytes])

    q := mLength / blockBytes
    r := mLength % blockBytes

    for i := 0; i < q; i++ {
        copy(M[0:], mData[i * blockBytes:])
        this.updateOffset(O)
        this.cipher.Encrypt(C, O)
        xor(C, M)
        copy(cData[i * blockBytes:], C[0:])
    }

    if r != 0 {
        copy(M[0:r], mData[q * blockBytes:])
        this.updateOffset(O)
        this.cipher.Encrypt(C, O)
        xor(C, M)
        copy(cData[q * blockBytes:], C[0:r])
    }
}

func (this *LetterSoup) updateOffset(O []byte) {
    // Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
    var O0 byte = O[0]

    copy(O[0:], O[1:12])

    O[9] = byte(O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
    O[10] = byte(O[10] ^ (O0 << 5) ^ (O0 << 3))
    O[11] = O0
}
