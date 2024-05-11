package sha0

const (
    // hash size
    Size = 20

    BlockSize = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [5]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

// newDigest returns a new *digest computing the checksum
func newDigest() *digest {
    d := new(digest)
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.s = initVal
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)
    for d.nx + plen >= BlockSize {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() (out []byte) {
    var dataLen = d.nx
    var blen = d.BlockSize()

    var currentLength = d.len * 8

    var countBuf [8]byte

    var lenlen = 8
    putu32(countBuf[lenlen - 8:], uint32(currentLength >> 32))
    putu32(countBuf[lenlen - 4:], uint32(currentLength))

    var endLen = (dataLen + lenlen + blen) & ^(blen - 1)
    d.Write([]byte{0x80})

    for i := dataLen + 1; i < endLen - lenlen; i++ {
        d.Write([]byte{0x00})
    }
    d.Write(countBuf[:])

    out = make([]byte, Size)

    for i := 0; i < 5; i++ {
        putu32(out[4 * i:], d.s[i])
    }

    return
}

func (d *digest) processBlock(data []byte) {
    currentVal := &d.s

    var A = currentVal[0]
    var B = currentVal[1]
    var C = currentVal[2]
    var D = currentVal[3]
    var E = currentVal[4]

    var W0 = getu32(data[0:]);
    E = ((A << 5) | (A >> 27)) + ((B & C) | (^B & D)) + E + W0 + 0x5A827999;
    B = (B << 30) | (B >> 2);

    var W1 = getu32(data[4:]);
    D = ((E << 5) | (E >> 27)) + ((A & B) | (^A & C)) + D + W1 + 0x5A827999;
    A = (A << 30) | (A >> 2);

    var W2 = getu32(data[8:]);
    C = ((D << 5) | (D >> 27)) + ((E & A) | (^E & B)) + C + W2 + 0x5A827999;
    E = (E << 30) | (E >> 2);

    var W3 = getu32(data[12:]);
    B = ((C << 5) | (C >> 27)) + ((D & E) | (^D & A)) + B + W3 + 0x5A827999;
    D = (D << 30) | (D >> 2);

    var W4 = getu32(data[16:]);
    A = ((B << 5) | (B >> 27)) + ((C & D) | (^C & E)) + A + W4 + 0x5A827999;
    C = (C << 30) | (C >> 2);

    var W5 = getu32(data[20:]);
    E = ((A << 5) | (A >> 27)) + ((B & C) | (^B & D)) + E + W5 + 0x5A827999;
    B = (B << 30) | (B >> 2);

    var W6 = getu32(data[24:]);
    D = ((E << 5) | (E >> 27)) + ((A & B) | (^A & C)) + D + W6 + 0x5A827999;
    A = (A << 30) | (A >> 2);

    var W7 = getu32(data[28:]);
    C = ((D << 5) | (D >> 27)) + ((E & A) | (^E & B)) + C + W7 + 0x5A827999;
    E = (E << 30) | (E >> 2);

    var W8 = getu32(data[32:]);
    B = ((C << 5) | (C >> 27)) + ((D & E) | (^D & A)) + B + W8 + 0x5A827999;
    D = (D << 30) | (D >> 2);

    var W9 = getu32(data[36:]);
    A = ((B << 5) | (B >> 27)) + ((C & D) | (^C & E)) + A + W9 + 0x5A827999;
    C = (C << 30) | (C >> 2);

    var Wa = getu32(data[40:]);
    E = ((A << 5) | (A >> 27)) + ((B & C) | (^B & D)) + E + Wa + 0x5A827999;
    B = (B << 30) | (B >> 2);

    var Wb = getu32(data[44:]);
    D = ((E << 5) | (E >> 27)) + ((A & B) | (^A & C)) + D + Wb + 0x5A827999;
    A = (A << 30) | (A >> 2);

    var Wc = getu32(data[48:]);
    C = ((D << 5) | (D >> 27)) + ((E & A) | (^E & B)) + C + Wc + 0x5A827999;
    E = (E << 30) | (E >> 2);

    var Wd = getu32(data[52:]);
    B = ((C << 5) | (C >> 27)) + ((D & E) | (^D & A)) + B + Wd + 0x5A827999;
    D = (D << 30) | (D >> 2);

    var We = getu32(data[56:]);
    A = ((B << 5) | (B >> 27)) + ((C & D) | (^C & E)) + A + We + 0x5A827999;
    C = (C << 30) | (C >> 2);

    var Wf = getu32(data[60:]);
    E = ((A << 5) | (A >> 27)) + ((B & C) | (^B & D)) + E + Wf + 0x5A827999;
    B = (B << 30) | (B >> 2);

    W0 = Wd ^ W8 ^ W2 ^ W0;
    D = ((E << 5) | (E >> 27)) + ((A & B) | (^A & C)) + D + W0 + 0x5A827999;
    A = (A << 30) | (A >> 2);
    W1 = We ^ W9 ^ W3 ^ W1;
    C = ((D << 5) | (D >> 27)) + ((E & A) | (^E & B)) + C + W1 + 0x5A827999;
    E = (E << 30) | (E >> 2);
    W2 = Wf ^ Wa ^ W4 ^ W2;
    B = ((C << 5) | (C >> 27)) + ((D & E) | (^D & A)) + B + W2 + 0x5A827999;
    D = (D << 30) | (D >> 2);
    W3 = W0 ^ Wb ^ W5 ^ W3;
    A = ((B << 5) | (B >> 27)) + ((C & D) | (^C & E)) + A + W3 + 0x5A827999;
    C = (C << 30) | (C >> 2);
    W4 = W1 ^ Wc ^ W6 ^ W4;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W4 + 0x6ED9EBA1;
    B = (B << 30) | (B >> 2);
    W5 = W2 ^ Wd ^ W7 ^ W5;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + W5 + 0x6ED9EBA1;
    A = (A << 30) | (A >> 2);
    W6 = W3 ^ We ^ W8 ^ W6;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + W6 + 0x6ED9EBA1;
    E = (E << 30) | (E >> 2);
    W7 = W4 ^ Wf ^ W9 ^ W7;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + W7 + 0x6ED9EBA1;
    D = (D << 30) | (D >> 2);
    W8 = W5 ^ W0 ^ Wa ^ W8;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + W8 + 0x6ED9EBA1;
    C = (C << 30) | (C >> 2);
    W9 = W6 ^ W1 ^ Wb ^ W9;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W9 + 0x6ED9EBA1;
    B = (B << 30) | (B >> 2);
    Wa = W7 ^ W2 ^ Wc ^ Wa;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + Wa + 0x6ED9EBA1;
    A = (A << 30) | (A >> 2);
    Wb = W8 ^ W3 ^ Wd ^ Wb;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + Wb + 0x6ED9EBA1;
    E = (E << 30) | (E >> 2);
    Wc = W9 ^ W4 ^ We ^ Wc;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + Wc + 0x6ED9EBA1;
    D = (D << 30) | (D >> 2);
    Wd = Wa ^ W5 ^ Wf ^ Wd;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + Wd + 0x6ED9EBA1;
    C = (C << 30) | (C >> 2);
    We = Wb ^ W6 ^ W0 ^ We;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + We + 0x6ED9EBA1;
    B = (B << 30) | (B >> 2);
    Wf = Wc ^ W7 ^ W1 ^ Wf;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + Wf + 0x6ED9EBA1;
    A = (A << 30) | (A >> 2);
    W0 = Wd ^ W8 ^ W2 ^ W0;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + W0 + 0x6ED9EBA1;
    E = (E << 30) | (E >> 2);
    W1 = We ^ W9 ^ W3 ^ W1;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + W1 + 0x6ED9EBA1;
    D = (D << 30) | (D >> 2);
    W2 = Wf ^ Wa ^ W4 ^ W2;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + W2 + 0x6ED9EBA1;
    C = (C << 30) | (C >> 2);
    W3 = W0 ^ Wb ^ W5 ^ W3;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W3 + 0x6ED9EBA1;
    B = (B << 30) | (B >> 2);
    W4 = W1 ^ Wc ^ W6 ^ W4;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + W4 + 0x6ED9EBA1;
    A = (A << 30) | (A >> 2);
    W5 = W2 ^ Wd ^ W7 ^ W5;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + W5 + 0x6ED9EBA1;
    E = (E << 30) | (E >> 2);
    W6 = W3 ^ We ^ W8 ^ W6;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + W6 + 0x6ED9EBA1;
    D = (D << 30) | (D >> 2);
    W7 = W4 ^ Wf ^ W9 ^ W7;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + W7 + 0x6ED9EBA1;
    C = (C << 30) | (C >> 2);
    W8 = W5 ^ W0 ^ Wa ^ W8;
    E = ((A << 5) | (A >> 27)) + ((B & C) | (B & D) | (C & D)) + E + W8 + 0x8F1BBCDC;
    B = (B << 30) | (B >> 2);
    W9 = W6 ^ W1 ^ Wb ^ W9;
    D = ((E << 5) | (E >> 27)) + ((A & B) | (A & C) | (B & C)) + D + W9 + 0x8F1BBCDC;
    A = (A << 30) | (A >> 2);
    Wa = W7 ^ W2 ^ Wc ^ Wa;
    C = ((D << 5) | (D >> 27)) + ((E & A) | (E & B) | (A & B)) + C + Wa + 0x8F1BBCDC;
    E = (E << 30) | (E >> 2);
    Wb = W8 ^ W3 ^ Wd ^ Wb;
    B = ((C << 5) | (C >> 27)) + ((D & E) | (D & A) | (E & A)) + B + Wb + 0x8F1BBCDC;
    D = (D << 30) | (D >> 2);
    Wc = W9 ^ W4 ^ We ^ Wc;
    A = ((B << 5) | (B >> 27)) + ((C & D) | (C & E) | (D & E)) + A + Wc + 0x8F1BBCDC;
    C = (C << 30) | (C >> 2);
    Wd = Wa ^ W5 ^ Wf ^ Wd;
    E = ((A << 5) | (A >> 27)) + ((B & C) | (B & D) | (C & D)) + E + Wd + 0x8F1BBCDC;
    B = (B << 30) | (B >> 2);
    We = Wb ^ W6 ^ W0 ^ We;
    D = ((E << 5) | (E >> 27)) + ((A & B) | (A & C) | (B & C)) + D + We + 0x8F1BBCDC;
    A = (A << 30) | (A >> 2);
    Wf = Wc ^ W7 ^ W1 ^ Wf;
    C = ((D << 5) | (D >> 27)) + ((E & A) | (E & B) | (A & B)) + C + Wf + 0x8F1BBCDC;
    E = (E << 30) | (E >> 2);

    W0 = Wd ^ W8 ^ W2 ^ W0;
    B = ((C << 5) | (C >> 27)) + ((D & E) | (D & A) | (E & A)) + B + W0 + 0x8F1BBCDC;
    D = (D << 30) | (D >> 2);
    W1 = We ^ W9 ^ W3 ^ W1;
    A = ((B << 5) | (B >> 27)) + ((C & D) | (C & E) | (D & E)) + A + W1 + 0x8F1BBCDC;
    C = (C << 30) | (C >> 2);
    W2 = Wf ^ Wa ^ W4 ^ W2;
    E = ((A << 5) | (A >> 27)) + ((B & C) | (B & D) | (C & D)) + E + W2 + 0x8F1BBCDC;
    B = (B << 30) | (B >> 2);
    W3 = W0 ^ Wb ^ W5 ^ W3;
    D = ((E << 5) | (E >> 27)) + ((A & B) | (A & C) | (B & C)) + D + W3 + 0x8F1BBCDC;
    A = (A << 30) | (A >> 2);
    W4 = W1 ^ Wc ^ W6 ^ W4;
    C = ((D << 5) | (D >> 27)) + ((E & A) | (E & B) | (A & B)) + C + W4 + 0x8F1BBCDC;
    E = (E << 30) | (E >> 2);
    W5 = W2 ^ Wd ^ W7 ^ W5;
    B = ((C << 5) | (C >> 27)) + ((D & E) | (D & A) | (E & A)) + B + W5 + 0x8F1BBCDC;
    D = (D << 30) | (D >> 2);
    W6 = W3 ^ We ^ W8 ^ W6;
    A = ((B << 5) | (B >> 27)) + ((C & D) | (C & E) | (D & E)) + A + W6 + 0x8F1BBCDC;
    C = (C << 30) | (C >> 2);
    W7 = W4 ^ Wf ^ W9 ^ W7;
    E = ((A << 5) | (A >> 27)) + ((B & C) | (B & D) | (C & D)) + E + W7 + 0x8F1BBCDC;
    B = (B << 30) | (B >> 2);
    W8 = W5 ^ W0 ^ Wa ^ W8;
    D = ((E << 5) | (E >> 27)) + ((A & B) | (A & C) | (B & C)) + D + W8 + 0x8F1BBCDC;
    A = (A << 30) | (A >> 2);
    W9 = W6 ^ W1 ^ Wb ^ W9;
    C = ((D << 5) | (D >> 27)) + ((E & A) | (E & B) | (A & B)) + C + W9 + 0x8F1BBCDC;
    E = (E << 30) | (E >> 2);
    Wa = W7 ^ W2 ^ Wc ^ Wa;
    B = ((C << 5) | (C >> 27)) + ((D & E) | (D & A) | (E & A)) + B + Wa + 0x8F1BBCDC;
    D = (D << 30) | (D >> 2);
    Wb = W8 ^ W3 ^ Wd ^ Wb;
    A = ((B << 5) | (B >> 27)) + ((C & D) | (C & E) | (D & E)) + A + Wb + 0x8F1BBCDC;
    C = (C << 30) | (C >> 2);
    Wc = W9 ^ W4 ^ We ^ Wc;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + Wc + 0xCA62C1D6;
    B = (B << 30) | (B >> 2);
    Wd = Wa ^ W5 ^ Wf ^ Wd;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + Wd + 0xCA62C1D6;
    A = (A << 30) | (A >> 2);
    We = Wb ^ W6 ^ W0 ^ We;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + We + 0xCA62C1D6;
    E = (E << 30) | (E >> 2);
    Wf = Wc ^ W7 ^ W1 ^ Wf;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + Wf + 0xCA62C1D6;
    D = (D << 30) | (D >> 2);

    W0 = Wd ^ W8 ^ W2 ^ W0;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + W0 + 0xCA62C1D6;
    C = (C << 30) | (C >> 2);
    W1 = We ^ W9 ^ W3 ^ W1;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W1 + 0xCA62C1D6;
    B = (B << 30) | (B >> 2);
    W2 = Wf ^ Wa ^ W4 ^ W2;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + W2 + 0xCA62C1D6;
    A = (A << 30) | (A >> 2);
    W3 = W0 ^ Wb ^ W5 ^ W3;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + W3 + 0xCA62C1D6;
    E = (E << 30) | (E >> 2);
    W4 = W1 ^ Wc ^ W6 ^ W4;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + W4 + 0xCA62C1D6;
    D = (D << 30) | (D >> 2);
    W5 = W2 ^ Wd ^ W7 ^ W5;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + W5 + 0xCA62C1D6;
    C = (C << 30) | (C >> 2);
    W6 = W3 ^ We ^ W8 ^ W6;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W6 + 0xCA62C1D6;
    B = (B << 30) | (B >> 2);
    W7 = W4 ^ Wf ^ W9 ^ W7;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + W7 + 0xCA62C1D6;
    A = (A << 30) | (A >> 2);
    W8 = W5 ^ W0 ^ Wa ^ W8;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + W8 + 0xCA62C1D6;
    E = (E << 30) | (E >> 2);
    W9 = W6 ^ W1 ^ Wb ^ W9;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + W9 + 0xCA62C1D6;
    D = (D << 30) | (D >> 2);
    Wa = W7 ^ W2 ^ Wc ^ Wa;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + Wa + 0xCA62C1D6;
    C = (C << 30) | (C >> 2);
    Wb = W8 ^ W3 ^ Wd ^ Wb;
    E = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + Wb + 0xCA62C1D6;
    B = (B << 30) | (B >> 2);
    Wc = W9 ^ W4 ^ We ^ Wc;
    D = ((E << 5) | (E >> 27)) + (A ^ B ^ C) + D + Wc + 0xCA62C1D6;
    A = (A << 30) | (A >> 2);
    Wd = Wa ^ W5 ^ Wf ^ Wd;
    C = ((D << 5) | (D >> 27)) + (E ^ A ^ B) + C + Wd + 0xCA62C1D6;
    E = (E << 30) | (E >> 2);
    We = Wb ^ W6 ^ W0 ^ We;
    B = ((C << 5) | (C >> 27)) + (D ^ E ^ A) + B + We + 0xCA62C1D6;
    D = (D << 30) | (D >> 2);
    Wf = Wc ^ W7 ^ W1 ^ Wf;
    A = ((B << 5) | (B >> 27)) + (C ^ D ^ E) + A + Wf + 0xCA62C1D6;
    C = (C << 30) | (C >> 2);

    currentVal[0] += A;
    currentVal[1] += B;
    currentVal[2] += C;
    currentVal[3] += D;
    currentVal[4] += E;
}
