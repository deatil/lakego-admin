// Package skein implements the Skein-512 hash function, MAC, and stream cipher
// as defined in "The Skein Hash Function Family, v1.3".
package skein512

import (
    "io"
    "hash"
    "errors"
    "crypto/cipher"
)

// Args can be used to configure hash function for different purposes.
// All fields are optional: if a field is nil, it will not be used.
type Args struct {
    // Key is a secret key for MAC, KDF, or stream cipher
    Key []byte
    // Person is a personalization string
    Person []byte
    // PublicKey is a public key for signature hashing
    PublicKey []byte
    // KeyId is a key identifier for KDF
    KeyId []byte
    // Nonce for stream cipher or randomized hashing
    Nonce []byte
    // NoMsg indicates whether message input is used by the function.
    NoMsg bool
}

// BlockSize is the block size of Skein-512 in bytes.
const BlockSize = 64

// Argument types (in the order they must be used).
const (
    keyArg       uint64 = 0
    configArg    uint64 = 4
    personArg    uint64 = 8
    publicKeyArg uint64 = 12
    keyIDArg     uint64 = 16
    nonceArg     uint64 = 20
    messageArg   uint64 = 48
    outputArg    uint64 = 63
)

const (
    firstBlockFlag uint64 = 1 << 62
    lastBlockFlag  uint64 = 1 << 63
)

var schemaId = []byte{'S', 'H', 'A', '3', 1, 0, 0, 0}
var outTweak = [2]uint64{8, outputArg<<56 | firstBlockFlag | lastBlockFlag}

// Precomputed initial values of state after configuration for unkeyed hashing.
var iv224 = [8]uint64{
    0xCCD0616248677224, 0xCBA65CF3A92339EF, 0x8CCD69D652FF4B64, 0x398AED7B3AB890B4,
    0x0F59D1B1457D2BD0, 0x6776FE6575D4EB3D, 0x99FBC70E997413E9, 0x9E2CFCCFE1C41EF7}

var iv256 = [8]uint64{
    0xCCD044A12FDB3E13, 0xE83590301A79A9EB, 0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
    0xEC06025E74DD7683, 0xE7A436CDC4746251, 0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13}

var iv384 = [8]uint64{
    0xA3F6C6BF3A75EF5F, 0xB0FEF9CCFD84FAA4, 0x9D77DD663D770CFE, 0xD798CBF3B468FDDA,
    0x1BC4A6668A0E4465, 0x7ED7D434E5807407, 0x548FC1ACD4EC44D6, 0x266E17546AA18FF8}

var iv512 = [8]uint64{
    0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
    0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33}

// Hash represents a state of Skein hash function.
// It implements hash.Hash interface.
type Hash struct {
    k [8]uint64 // chain value
    t [2]uint64 // tweak

    x  [64]byte // buffer
    nx int      // number of bytes in buffer

    outLen uint64 // output length in bytes
    noMsg  bool   // true if message block argument should not be used

    ik [8]uint64 // copy of initial chain value
}

func (h *Hash) hashBlock(b []byte, unpaddedLen uint64) {
    var u [8]uint64

    // Update block counter.
    h.t[0] += unpaddedLen

    u[0] = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
        uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
    u[1] = uint64(b[8]) | uint64(b[9])<<8 | uint64(b[10])<<16 | uint64(b[11])<<24 |
        uint64(b[12])<<32 | uint64(b[13])<<40 | uint64(b[14])<<48 | uint64(b[15])<<56
    u[2] = uint64(b[16]) | uint64(b[17])<<8 | uint64(b[18])<<16 | uint64(b[19])<<24 |
        uint64(b[20])<<32 | uint64(b[21])<<40 | uint64(b[22])<<48 | uint64(b[23])<<56
    u[3] = uint64(b[24]) | uint64(b[25])<<8 | uint64(b[26])<<16 | uint64(b[27])<<24 |
        uint64(b[28])<<32 | uint64(b[29])<<40 | uint64(b[30])<<48 | uint64(b[31])<<56
    u[4] = uint64(b[32]) | uint64(b[33])<<8 | uint64(b[34])<<16 | uint64(b[35])<<24 |
        uint64(b[36])<<32 | uint64(b[37])<<40 | uint64(b[38])<<48 | uint64(b[39])<<56
    u[5] = uint64(b[40]) | uint64(b[41])<<8 | uint64(b[42])<<16 | uint64(b[43])<<24 |
        uint64(b[44])<<32 | uint64(b[45])<<40 | uint64(b[46])<<48 | uint64(b[47])<<56
    u[6] = uint64(b[48]) | uint64(b[49])<<8 | uint64(b[50])<<16 | uint64(b[51])<<24 |
        uint64(b[52])<<32 | uint64(b[53])<<40 | uint64(b[54])<<48 | uint64(b[55])<<56
    u[7] = uint64(b[56]) | uint64(b[57])<<8 | uint64(b[58])<<16 | uint64(b[59])<<24 |
        uint64(b[60])<<32 | uint64(b[61])<<40 | uint64(b[62])<<48 | uint64(b[63])<<56

    block(&h.k, &h.t, &h.k, &u)

    // Clear first block flag.
    h.t[1] &^= firstBlockFlag
}

// Reset resets hash to its state after initialization.
// If hash was initialized with arguments, such as key,
// these arguments are preserved.
func (h *Hash) Reset() {
    // Restore initial chain value.
    h.k = h.ik
    // Reset buffer.
    h.nx = 0
    // Init tweak to first message block.
    h.t[0] = 0
    h.t[1] = messageArg<<56 | firstBlockFlag
}

// Size returns the number of bytes Sum will return.
// If the hash was created with output size greater than the maximum
// size of int, the result is undefined.
func (h *Hash) Size() int {
    return int(h.outLen)
}

// BlockSize returns the hash's underlying block size.
func (h *Hash) BlockSize() int {
    return BlockSize
}

func (h *Hash) hashLastBlock() {
    // Pad buffer with zeros.
    for i := h.nx; i < len(h.x); i++ {
        h.x[i] = 0
    }
    // Set last block flag.
    h.t[1] |= lastBlockFlag
    // Process last block.
    h.hashBlock(h.x[:], uint64(h.nx))
    h.nx = 0
}

func (h *Hash) outputBlock(dst *[64]byte, counter uint64) {
    var u [8]uint64
    u[0] = counter
    block(&h.k, &outTweak, &u, &u)
    for i, v := range u {
        dst[i*8+0] = byte(v)
        dst[i*8+1] = byte(v >> 8)
        dst[i*8+2] = byte(v >> 16)
        dst[i*8+3] = byte(v >> 24)
        dst[i*8+4] = byte(v >> 32)
        dst[i*8+5] = byte(v >> 40)
        dst[i*8+6] = byte(v >> 48)
        dst[i*8+7] = byte(v >> 56)
    }
}

func (h *Hash) appendOutput(length uint64) []byte {
    var b [64]byte
    var counter uint64

    var out []byte

    for length > 0 {
        h.outputBlock(&b, counter)
        counter++ // increment counter
        if length < 64 {
            out = append(out, b[:length]...)
            break
        }

        out = append(out, b[:]...)
        length -= 64
    }

    return out
}

func (h *Hash) update(b []byte) {
    left := 64 - h.nx
    if len(b) > left {
        // Process leftovers.
        copy(h.x[h.nx:], b[:left])
        b = b[left:]
        h.hashBlock(h.x[:], 64)
        h.nx = 0
    }

    // Process full blocks except for the last one.
    for len(b) > 64 {
        h.hashBlock(b, 64)
        b = b[64:]
    }

    // Save leftovers.
    h.nx += copy(h.x[h.nx:], b)
}

// Write adds more data to the running hash.
// It never returns an error.
func (h *Hash) Write(b []byte) (n int, err error) {
    if h.noMsg {
        return 0, errors.New("Skein: can't write to a function configured with NoMsg")
    }
    h.update(b)
    return len(b), nil
}

// Sum appends the current hash to in and returns the resulting slice.
// It does not change the underlying hash state.
func (h *Hash) Sum(p []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *h
    hash := d0.checkSum()
    return append(p, hash...)
}

func (h *Hash) checkSum() (hash []byte) {
    if !h.noMsg {
        // Finalize message.
        h.hashLastBlock()
    }

    return h.appendOutput(h.outLen)
}

// OutputReader returns an io.Reader that can be used to read
// arbitrary-length output of the hash.
// Reading from it doesn't change the underlying hash state.
func (h *Hash) OutputReader() io.Reader {
    return newOutputReader(h)
}

// outputReader implements io.Reader and cipher.Stream interfaces.
// It is used for reading arbitrary-length output of Skein.
type outputReader struct {
    Hash
    counter uint64
}

// newOutputReader returns a new outputReader initialized with
// a copy of the given hash.
func newOutputReader(h *Hash) *outputReader {
    // Initialize with the copy of h.
    r := &outputReader{Hash: *h}
    if !r.noMsg {
        // Finalize message.
        r.hashLastBlock()
    }
    // Set buffer position to end.
    r.nx = BlockSize
    return r
}

// nextBlock puts the next hash output block into the internal buffer.
func (r *outputReader) nextBlock() {
    r.outputBlock(&r.x, r.counter)
    r.counter++ // increment counter
    r.nx = 0
}

// Read puts the next len(p) bytes of hash output into p.
// It never returns an error.
func (r *outputReader) Read(p []byte) (n int, err error) {
    n = len(p)
    left := BlockSize - r.nx

    if len(p) < left {
        r.nx += copy(p, r.x[r.nx:r.nx+len(p)])
        return
    }

    copy(p, r.x[r.nx:])
    p = p[left:]
    r.nextBlock()

    for len(p) >= BlockSize {
        copy(p, r.x[:])
        p = p[BlockSize:]
        r.nextBlock()
    }
    if len(p) > 0 {
        r.nx += copy(p, r.x[:len(p)])
    }
    return
}

// XORKeyStream XORs each byte in the given slice with the next byte from the
// hash output. Dst and src may point to the same memory.
func (r *outputReader) XORKeyStream(dst, src []byte) {
    left := BlockSize - r.nx

    if len(src) < left {
        for i, v := range src {
            dst[i] = v ^ r.x[r.nx]
            r.nx++
        }
        return
    }

    for i, b := range r.x[r.nx:] {
        dst[i] = src[i] ^ b
    }
    dst = dst[left:]
    src = src[left:]
    r.nextBlock()

    for len(src) >= BlockSize {
        for i, v := range src[:BlockSize] {
            dst[i] = v ^ r.x[i]
        }
        dst = dst[BlockSize:]
        src = src[BlockSize:]
        r.nextBlock()
    }
    if len(src) > 0 {
        for i, v := range src {
            dst[i] = v ^ r.x[i]
            r.nx++
        }
    }
}

// addArg adds Skein argument into the hash state.
func (h *Hash) addArg(argType uint64, arg []byte) {
    h.t[0] = 0
    h.t[1] = argType<<56 | firstBlockFlag
    h.update(arg)
    h.hashLastBlock()
}

// addConfig adds configuration block into the hash state.
func (h *Hash) addConfig(outBits uint64) {
    var c [32]byte
    copy(c[:], schemaId)
    c[8] = byte(outBits)
    c[9] = byte(outBits >> 8)
    c[10] = byte(outBits >> 16)
    c[11] = byte(outBits >> 24)
    c[12] = byte(outBits >> 32)
    c[13] = byte(outBits >> 40)
    c[14] = byte(outBits >> 48)
    c[15] = byte(outBits >> 56)
    h.addArg(configArg, c[:])
}

// New returns a new skein.Hash configured with the given arguments. The final
// output length of hash function in bytes is outLen (for example, 64 when
// calculating 512-bit hash). Configuration arguments may be nil.
func New(outLen uint64, args *Args) *Hash {
    h := new(Hash)
    h.outLen = outLen

    if args != nil && args.Key != nil {
        // Key argument comes before configuration.
        h.addArg(keyArg, args.Key)
        // Configuration.
        h.addConfig(outLen * 8)
    } else {
        // Configuration without key.
        // Try using precomputed values for common sizes.
        switch outLen {
            case 224 / 8:
                h.k = iv224
            case 256 / 8:
                h.k = iv256
            case 384 / 8:
                h.k = iv384
            case 512 / 8:
                h.k = iv512
            default:
                h.addConfig(outLen * 8)
        }
    }

    // Other arguments, in specified order.
    if args != nil {
        h.noMsg = args.NoMsg

        if args.Person != nil {
            h.addArg(personArg, args.Person)
        }
        if args.PublicKey != nil {
            h.addArg(publicKeyArg, args.PublicKey)
        }
        if args.KeyId != nil {
            h.addArg(keyIDArg, args.KeyId)
        }
        if args.Nonce != nil {
            h.addArg(nonceArg, args.Nonce)
        }
    }

    // Init tweak to first message block.
    h.t[0] = 0
    h.t[1] = messageArg<<56 | firstBlockFlag

    // Save a copy of initial chain value for Reset.
    h.ik = h.k
    return h
}

// NewHash returns hash.Hash calculating checksum of the given length in bytes
// (for example, to calculate 256-bit hash, outLen must be set to 32).
func NewHash(outLen uint64) hash.Hash {
    return hash.Hash(New(outLen, nil))
}

// NewMAC returns hash.Hash calculating Skein Message Authentication Code of the
// given length in bytes. A MAC is a cryptographic hash that uses a key to
// authenticate a message. The receiver verifies the hash by recomputing it
// using the same key.
func NewMAC(outLen uint64, key []byte) hash.Hash {
    return hash.Hash(New(outLen, &Args{Key: key}))
}

// NewStream returns a cipher.Stream for encrypting a message with the given key
// and nonce. The same key-nonce combination must not be used to encrypt more
// than one message. There are no limits on the length of key or nonce.
func NewStream(key []byte, nonce []byte) cipher.Stream {
    const streamOutLen = (1<<64 - 1) / 8 // 2^64 - 1 bits
    h := New(streamOutLen, &Args{Key: key, Nonce: nonce, NoMsg: true})
    return newOutputReader(h)
}
