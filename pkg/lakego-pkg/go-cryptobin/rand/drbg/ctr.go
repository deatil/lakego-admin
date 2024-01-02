package drbg

import (
    "bytes"
    "errors"
    "crypto/subtle"
    "crypto/cipher"
    "encoding/binary"
)

type BlockCipher = func(key []byte) (cipher.Block, error)

type ctrDRBG struct {
    newCipher BlockCipher

    keyLen     int
    seedLength int

    v             []byte
    key           []byte
    reseedCounter uint64
}

func NewCTR(cip BlockCipher, keyLen int, entropy, nonce, personalstr []byte) (*ctrDRBG, error) {
    if len(entropy) <= 0 ||  len(entropy) >= MAX_BYTES {
        return nil, errors.New("invalid entropy length")
    }

    if len(nonce) == 0 || len(nonce) >= MAX_BYTES>>1 {
        return nil, errors.New("invalid nonce length")
    }

    if len(personalstr) >= MAX_BYTES {
        return nil, errors.New("personalization is too long")
    }

    d := &ctrDRBG{
        newCipher: cip,
        keyLen:    keyLen,
        key:       make([]byte, keyLen),
    }

    c, err := cip(d.key)
    if err != nil {
        return nil, err
    }

    blockSize := c.BlockSize()
    d.seedLength = keyLen + blockSize

    d.v = make([]byte, blockSize)

    d.init(entropy, nonce, personalstr)

    return d, nil
}

func (this *ctrDRBG) init(entropy, nonce, personalstr []byte) {
    var seed bytes.Buffer

    seed.Write(entropy)
    seed.Write(nonce)
    seed.Write(personalstr)
    seedMaterial := seed.Bytes()

    seedMaterial = this.blockCipherDF(seedMaterial, this.seedLength)

    // CTR_DRBG_Update(seed_material, Key, V)
    this.update(seedMaterial)

    this.reseedCounter = 1
}

func (this *ctrDRBG) Reseed(entropy, additional []byte) error {
    if len(entropy) <= 0 ||  len(entropy) >= MAX_BYTES {
        return errors.New("invalid entropy length")
    }

    if len(additional) >= MAX_BYTES {
        return errors.New("additional input too long")
    }

    var tmp bytes.Buffer

    tmp.Write(entropy)
    tmp.Write(additional)
    seedMaterial := tmp.Bytes()

    seedMaterial = this.blockCipherDF(seedMaterial, this.seedLength)

    this.update(seedMaterial)

    this.reseedCounter = 1

    return nil
}

func (this *ctrDRBG) Generate(out, additional []byte) error {
    if this.reseedCounter > 1<<48 {
        return ErrReseedRequired
    }

    if len(additional) > 0 {
        additional = this.blockCipherDF(additional, this.seedLength)

        this.update(additional)
    } else {
        additional = make([]byte, this.seedLength)
    }

    var temp bytes.Buffer

    blockSize := len(this.v)
    for temp.Len() < len(out) {
        drbg_add1(this.v, blockSize)

        outputBlock := make([]byte, blockSize)
        this.encrypt(this.key, outputBlock, this.v)

        temp.Write(outputBlock)
    }

    copy(out, temp.Bytes())

    this.update(additional)

    this.reseedCounter += 1

    return nil
}

func (this *ctrDRBG) update(seedMaterial []byte) {
    temp := make([]byte, this.seedLength)

    outlen := len(this.v)
    v := make([]byte, outlen)

    copy(v, this.v)

    output := make([]byte, outlen)
    for i := 0; i < (this.seedLength+outlen-1)/outlen; i++ {
        drbg_add1(v, outlen)

        this.encrypt(this.key, output, v)

        copy(temp[i*outlen:], output)
    }

    // temp = temp XOR seed_material
    subtle.XORBytes(temp, temp, seedMaterial)

    // Key = leftmost(temp, key_length)
    copy(this.key, temp)

    // V = rightmost(temp, outlen)
    copy(this.v, temp[this.keyLen:])
}

// bcc implements BCC, described in section 10.3.3 of SP800-90A.
func (this *ctrDRBG) bcc(key, data []byte) []byte {
    bs := len(this.v)

    value := make([]byte, bs)

    for i := 0; i < len(data)/bs; i++ {
        subtle.XORBytes(value, value, data[i*bs:])

        this.encrypt(key, value, value)
    }

    return value
}

// blockCipherDF implements Block_Cipher_df, described in section 10.3.2 of SP800-90A.
func (this *ctrDRBG) blockCipherDF(input []byte, requestedBytes int) []byte {
    bs := len(this.v)
    keyLen := this.keyLen

    l := uint32(len(input))
    n := uint32(requestedBytes)

    var s bytes.Buffer
    binary.Write(&s, binary.BigEndian, l)
    binary.Write(&s, binary.BigEndian, n)
    s.Write(input)
    s.Write([]byte{0x80})

    paddingSize := bs - s.Len()%bs
    s.Write(bytes.Repeat([]byte{0x00}, paddingSize))

    key := make([]byte, keyLen)
    for i := 0; i < keyLen; i++ {
        key[i] = byte(i)
    }

    iv := make([]byte, bs)

    var temp bytes.Buffer

    for i := uint32(0); temp.Len() < (keyLen + bs); i++ {
        binary.BigEndian.PutUint32(iv, i)

        var data bytes.Buffer
        data.Write(iv)
        data.Write(s.Bytes())

        temp.Write(this.bcc(key, data.Bytes()))
    }

    tempBytes := temp.Bytes()

    k := make([]byte, keyLen)
    copy(k, tempBytes)

    x := make([]byte, bs)
    copy(x, tempBytes[keyLen:])

    temp.Reset()

    for temp.Len() < requestedBytes {
        this.encrypt(k, x, x)

        temp.Write(x)
    }

    tempBytes = temp.Bytes()
    return tempBytes[:requestedBytes]
}

func (this *ctrDRBG) encrypt(key, out, in []byte) {
    block, err := this.newCipher(key)
    if err != nil {
        panic(err)
    }

    block.Encrypt(out, in)
}
