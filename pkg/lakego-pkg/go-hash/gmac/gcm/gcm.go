package gcm

const (
    GCMBlockSize         = 16
    GCMTagSize           = 16
    GCMMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
    GCMStandardNonceSize = 12
)

// counterCrypt crypts in to out using g.cipher in counter mode.
func GCMCounterCrypt(out, in []byte, c Block, counter *[GCMBlockSize]byte) {
    var ctr CTR
    ctr.Init(c, counter[:], 4)
    ctr.Xor(out, in)
    ctr.CopyCTR(counter[:])
}

// GCMFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
type GCMFieldElement struct {
    Low, High uint64
}

var (
    gcmInit          func(g *GCM, cipher Block)
    gcmDeriveCounter func(g *GCM, counter *[GCMBlockSize]byte, nonce []byte)
    gcmUpdate        func(g *GCM, y *GCMFieldElement, blocks []byte)
    gcmAuth          func(g *GCM, out, ciphertext, additionalData []byte, tagMask *[GCMTagSize]byte)
    gcmFinish        func(g *GCM, out []byte, y *GCMFieldElement, ciphertextLen, additionalDataLen int, tagMask *[GCMTagSize]byte)
)

// GCM represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/GCM/GCM-revised-spec.pdf
type GCM struct {
    // productTable contains the first sixteen powers of the key, H.
    // However, they are in bit reversed order. See NewGCMWithNonceSize.
    productTable [16]GCMFieldElement
}

func (g *GCM) Init(cipher Block) {
    gcmInit(g, cipher)
}

func (g *GCM) DeriveCounter(counter *[GCMBlockSize]byte, nonce []byte) {
    gcmDeriveCounter(g, counter, nonce)
}

func (g *GCM) Update(y *GCMFieldElement, blocks []byte) {
    if len(blocks) == 0 {
        return
    }

    gcmUpdate(g, y, blocks)
}

func (g *GCM) Auth(out, ciphertext, additionalData []byte, tagMask *[GCMTagSize]byte) {
    gcmAuth(g, out, ciphertext, additionalData, tagMask)
}

func (g *GCM) Finish(out []byte, y *GCMFieldElement, ciphertextLen, additionalDataLen int, tagMask *[GCMTagSize]byte) {
    gcmFinish(g, out, y, ciphertextLen, additionalDataLen, tagMask)
}
