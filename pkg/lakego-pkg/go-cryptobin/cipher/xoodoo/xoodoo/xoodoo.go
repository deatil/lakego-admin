package xoodoo

import (
    "fmt"
    "math/bits"
    "encoding/binary"
)

// Package xoodoo implements the Xoodoo cryptographic permutation function from which a variety of
// other cryptographic primitives and modes can be built. Xoodoo operates on a 384-bit state, realized
// here as an array of twelve(12) 32-bit unsigned integers, to generate a new pseudo-random state each time
// the permutation is applied. In addition to the main constructor and permutation functions, a variety
// of other helper methods are provided to manipulate the underlying state bytes.

const (
    // MaxRounds is current ceiling on how many iterations of Xoodoo can be done in the permutation
    // function
    MaxRounds = 12
    // StateSizeBytes describes the Xoodoo object in term of the number of bytes it is made up of
    StateSizeBytes = 48
    // StateSizeWords describes the Xoodoo object in term of the number of 32-bit unsigned ints it is made up of
    StateSizeWords = 12
)

var (
    // RoundConstants is the sequence of 32-bit constants applied in each round of Xoodoo
    RoundConstants = [StateSizeWords]uint32{
        0x00000058,
        0x00000038,
        0x000003C0,
        0x000000D0,
        0x00000120,
        0x00000014,
        0x00000060,
        0x0000002C,
        0x00000380,
        0x000000F0,
        0x000001A0,
        0x00000012,
    }
)

// State represents the 384-bit Xoodoo object as a collection of uint32 words
type State [StateSizeWords]uint32

// Xoodoo combines the xoodoo state with additional configuration for completing the
// permutation operation
type Xoodoo struct {
    State  State
    rounds int
    tmp    State
    p      [4]uint32
    e      [4]uint32
}

// XorState performs the exclusive-or operation on two XoodooState objects and returns
// the resulting XoodooState
func XorState(a, b State) State {
    return State{
        a[0] ^ b[0],
        a[1] ^ b[1],
        a[2] ^ b[2],
        a[3] ^ b[3],
        a[4] ^ b[4],
        a[5] ^ b[5],
        a[6] ^ b[6],
        a[7] ^ b[7],
        a[8] ^ b[8],
        a[9] ^ b[9],
        a[10] ^ b[10],
        a[11] ^ b[11],
    }
}

// XorStateBytes performs an exclusive-or between the input byte slice and
// the underlying XoodooState. The result is saved to the internal state
func (xds *State) XorStateBytes(in []byte) {
    xds[0] ^= (binary.LittleEndian.Uint32(in[0:4]))
    xds[1] ^= (binary.LittleEndian.Uint32(in[4:8]))
    xds[2] ^= (binary.LittleEndian.Uint32(in[8:12]))
    xds[3] ^= (binary.LittleEndian.Uint32(in[12:16]))
    xds[4] ^= (binary.LittleEndian.Uint32(in[16:20]))
    xds[5] ^= (binary.LittleEndian.Uint32(in[20:24]))
    xds[6] ^= (binary.LittleEndian.Uint32(in[24:28]))
    xds[7] ^= (binary.LittleEndian.Uint32(in[28:32]))
    xds[8] ^= (binary.LittleEndian.Uint32(in[32:36]))
    xds[9] ^= (binary.LittleEndian.Uint32(in[36:40]))
    xds[10] ^= (binary.LittleEndian.Uint32(in[40:44]))
    xds[11] ^= (binary.LittleEndian.Uint32(in[44:48]))
}

// XorByte performs an exclusive-or between a single provide byte and byte
// within the underlying XoodooState based on the provided offset. The result
// is stored in the XoodooState
func (xds *State) XorByte(x byte, offset int) error {
    if offset < 0 || offset >= StateSizeBytes {
        return fmt.Errorf("go-cryptobin/xoodoo: xor byte offset out of range:%d", offset)
    }

    xInt := uint32(x) << (8 * (offset % 4))
    xds[(offset >> 2)] ^= xInt
    return nil
}

// XorExtractBytes performs an exclusive-or between a provided number of bytes and a matching number
// of bytes of the underlying Xoodoo state starting from offset 0.
func (xd *Xoodoo) XorExtractBytes(x []byte) ([]byte, error) {
    size := len(x)
    if size <= 0 || size > StateSizeBytes {
        return nil, fmt.Errorf("go-cryptobin/xoodoo: xor and extract bytes size out of range:%d", size)
    }
    out := make([]byte, size)
    stateBytes := xd.Bytes()
    for i := 0; i < size; i++ {
        out[i] = stateBytes[i] ^ x[i]
    }
    return out, nil
}

// UnmarshalBinary converts provide byte slice to the Xoodoo state format
// This method allows State to satisfy the encoding.BinaryUnmarshaler interface
func (xds *State) UnmarshalBinary(data []byte) error {
    if len(data) != StateSizeBytes {
        return fmt.Errorf("go-cryptobin/xoodoo: input data (%d bytes) != xoodoo state size (%d bytes)", len(data), StateSizeBytes)
    }

    xds[0] = (binary.LittleEndian.Uint32(data[0:4]))
    xds[1] = (binary.LittleEndian.Uint32(data[4:8]))
    xds[2] = (binary.LittleEndian.Uint32(data[8:12]))
    xds[3] = (binary.LittleEndian.Uint32(data[12:16]))
    xds[4] = (binary.LittleEndian.Uint32(data[16:20]))
    xds[5] = (binary.LittleEndian.Uint32(data[20:24]))
    xds[6] = (binary.LittleEndian.Uint32(data[24:28]))
    xds[7] = (binary.LittleEndian.Uint32(data[28:32]))
    xds[8] = (binary.LittleEndian.Uint32(data[32:36]))
    xds[9] = (binary.LittleEndian.Uint32(data[36:40]))
    xds[10] = (binary.LittleEndian.Uint32(data[40:44]))
    xds[11] = (binary.LittleEndian.Uint32(data[44:48]))
    return nil
}

// MarshalBinary converts the Xoodoo state of the receiver to slice of bytes
// This method allows State to satisfy the encoding.BinaryMarshaler interface
func (xds *State) MarshalBinary() (data []byte, err error) {
    data = make([]byte, StateSizeBytes)
    binary.LittleEndian.PutUint32(data[0:4], xds[0])
    binary.LittleEndian.PutUint32(data[4:8], xds[1])
    binary.LittleEndian.PutUint32(data[8:12], xds[2])
    binary.LittleEndian.PutUint32(data[12:16], xds[3])
    binary.LittleEndian.PutUint32(data[16:20], xds[4])
    binary.LittleEndian.PutUint32(data[20:24], xds[5])
    binary.LittleEndian.PutUint32(data[24:28], xds[6])
    binary.LittleEndian.PutUint32(data[28:32], xds[7])
    binary.LittleEndian.PutUint32(data[32:36], xds[8])
    binary.LittleEndian.PutUint32(data[36:40], xds[9])
    binary.LittleEndian.PutUint32(data[40:44], xds[10])
    binary.LittleEndian.PutUint32(data[44:48], xds[11])
    return data, nil
}

// NewXoodoo returns a new Xoodoo object initialized with the desired number of rounds
// for the permutation function to execute
func NewXoodoo(rounds int, state [StateSizeBytes]byte) (*Xoodoo, error) {
    var x Xoodoo
    x.rounds = rounds
    if rounds > len(RoundConstants) {
        return nil, fmt.Errorf("go-cryptobin/xoodoo: invalid number of rounds: %d", rounds)
    }

    err := x.State.UnmarshalBinary(state[:])
    if err != nil {
        return nil, fmt.Errorf("go-cryptobin/xoodoo: invalid initial state:%s", err)
    }

    return &x, nil
}

// Bytes returns the internal Xoodoo state as a slice of bytes
func (xd *Xoodoo) Bytes() []byte {
    buf, _ := xd.State.MarshalBinary()
    return buf
}

// Permutation executes an optimized implementation of Xoodoo permutation operation over the
//provided  xoodoo state
func (xd *Xoodoo) Permutation() {
    for i := MaxRounds - xd.rounds; i < MaxRounds; i++ {
        xd.p = [4]uint32{
            xd.State[0] ^ xd.State[4] ^ xd.State[8],
            xd.State[1] ^ xd.State[5] ^ xd.State[9],
            xd.State[2] ^ xd.State[6] ^ xd.State[10],
            xd.State[3] ^ xd.State[7] ^ xd.State[11],
        }
        xd.e = [4]uint32{
            bits.RotateLeft32(xd.p[3], 5) ^ bits.RotateLeft32(xd.p[3], 14),
            bits.RotateLeft32(xd.p[0], 5) ^ bits.RotateLeft32(xd.p[0], 14),
            bits.RotateLeft32(xd.p[1], 5) ^ bits.RotateLeft32(xd.p[1], 14),
            bits.RotateLeft32(xd.p[2], 5) ^ bits.RotateLeft32(xd.p[2], 14),
        }

        xd.tmp[0] = xd.e[0] ^ xd.State[0] ^ RoundConstants[i]
        xd.tmp[1] = xd.e[1] ^ xd.State[1]
        xd.tmp[2] = xd.e[2] ^ xd.State[2]
        xd.tmp[3] = xd.e[3] ^ xd.State[3]

        xd.tmp[4] = xd.e[3] ^ xd.State[7]
        xd.tmp[5] = xd.e[0] ^ xd.State[4]
        xd.tmp[6] = xd.e[1] ^ xd.State[5]
        xd.tmp[7] = xd.e[2] ^ xd.State[6]

        xd.tmp[8] = bits.RotateLeft32(xd.e[0]^xd.State[8], 11)
        xd.tmp[9] = bits.RotateLeft32(xd.e[1]^xd.State[9], 11)
        xd.tmp[10] = bits.RotateLeft32(xd.e[2]^xd.State[10], 11)
        xd.tmp[11] = bits.RotateLeft32(xd.e[3]^xd.State[11], 11)

        xd.State[0] = (^xd.tmp[4] & xd.tmp[8]) ^ xd.tmp[0]
        xd.State[1] = (^xd.tmp[5] & xd.tmp[9]) ^ xd.tmp[1]
        xd.State[2] = (^xd.tmp[6] & xd.tmp[10]) ^ xd.tmp[2]
        xd.State[3] = (^xd.tmp[7] & xd.tmp[11]) ^ xd.tmp[3]

        xd.State[4] = bits.RotateLeft32((^xd.tmp[8]&xd.tmp[0])^xd.tmp[4], 1)
        xd.State[5] = bits.RotateLeft32((^xd.tmp[9]&xd.tmp[1])^xd.tmp[5], 1)
        xd.State[6] = bits.RotateLeft32((^xd.tmp[10]&xd.tmp[2])^xd.tmp[6], 1)
        xd.State[7] = bits.RotateLeft32((^xd.tmp[11]&xd.tmp[3])^xd.tmp[7], 1)

        xd.State[8] = bits.RotateLeft32((^xd.tmp[2]&xd.tmp[6])^xd.tmp[10], 8)
        xd.State[9] = bits.RotateLeft32((^xd.tmp[3]&xd.tmp[7])^xd.tmp[11], 8)
        xd.State[10] = bits.RotateLeft32((^xd.tmp[0]&xd.tmp[4])^xd.tmp[8], 8)
        xd.State[11] = bits.RotateLeft32((^xd.tmp[1]&xd.tmp[5])^xd.tmp[9], 8)

    }
    xd.tmp = State{}
    xd.e = [4]uint32{}
    xd.p = [4]uint32{}
}
