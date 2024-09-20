package k12

import (
    "errors"
)

const (
    // size of a K12 chunk
    BlockSize = 8192
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    customString    []byte
    phase           spongeDirection // to avoid absorbing when we're already in the squeezing phase
    state           *state          // the main state
    numChunk        int             // needed for logic and padding
    currentChunk    *state          // not for the first chunk
    currentWritten  int             // needed to know if we switch to a different chunk
    tempChunkOutput [32]byte        // needed to truncate a chunk's output
    hashSize        int             // output hashed data length
}

// newDigest returns a new *digest computing the checksum
func newDigest(customString []byte, hashSize int) *digest {
    d := &digest{
        customString: customString,
        state:        &state{rate: 168},
        currentChunk: &state{rate: 168, dsbyte: 0x0b},
        hashSize:     hashSize,
    }
    d.Reset()

    return d
}

// Allows you to re-use a K12 instance.
func (t *digest) Reset() {
    t.state.Reset()
    t.currentChunk.Reset()
    t.phase = spongeAbsorbing
}

func (d *digest) Size() int {
    return d.hashSize
}

func (d *digest) BlockSize() int {
    return BlockSize
}

// Write absorbs more data into the hash's state.
func (t *digest) Write(p []byte) (nn int, err error) {
    if t.phase != spongeAbsorbing {
        err = errors.New("go-hash/k12: cannot write after read")
        return
    }

    nn = len(p)

    for len(p) > 0 {
        // we reached the end of the chunk → we create a new chunk
        if t.currentWritten == BlockSize {
            if t.numChunk == 0 {
                // pad the main state
                t.state.Write([]byte{0x03, 0, 0, 0, 0, 0, 0, 0}) // 110^62
            } else {
                // truncate + write the chunk
                t.currentChunk.Read(t.tempChunkOutput[:]) // padding is in dsByte of t.currentChunk
                t.state.Write(t.tempChunkOutput[:])
                t.currentChunk.Reset()
            }

            // on to the new chunk!
            t.currentWritten = 0
            t.numChunk++
        }

        // we figure out how much data we can write
        xx := BlockSize - t.currentWritten
        if xx > len(p) {
            xx = len(p)
        }

        var written int
        if t.numChunk == 0 {
            written, _ = t.state.Write(p[:xx])
        } else {
            written, _ = t.currentChunk.Write(p[:xx])
        }

        t.currentWritten += written

        // what's left for the loop
        p = p[xx:]
    }

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := d.clone()
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() (out []byte) {
    hash := make([]byte, d.hashSize)
    d.Read(hash)
    return hash
}

// Reads data. This can be used infinitely (pretty much)
func (t *digest) Read(out []byte) (n int, err error) {
    // finish absorbing → padding
    if t.phase == spongeAbsorbing {
        // custom string
        t.Write(t.customString)
        t.Write(rightEncode(uint64(len(t.customString))))

        // padding
        if t.numChunk == 0 {
            // one chunk
            t.state.dsbyte = 0x07 // 11|10 0000
        } else {
            // many chunks
            t.currentChunk.Read(t.tempChunkOutput[:]) // padding is in dsByte of t.currentChunk
            t.state.Write(t.tempChunkOutput[:])

            t.state.Write(rightEncode(uint64(t.numChunk)))
            t.state.Write([]byte{0xff, 0xff})
            t.state.dsbyte = 0x06 // 01|10 0000
        }

        t.phase = spongeSqueezing
    }

    // rely on the sponge's function to read
    n, err = t.state.Read(out)

    return
}

func (d *digest) clone() *digest {
    d0 := *d

    copy(d0.customString, d.customString)

    d0.state = d.state.clone()
    d0.currentChunk = d.currentChunk.clone()

    return &d0
}
