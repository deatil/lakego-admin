package rabin

// digest computes Rabin hashes (often called fingerprints).
//
// digest implements hash.Hash64.
type digest struct {
    tab  *Table
    hash uint64
    msg  []byte
    pos  int
}

// newDigest returns a new digest using the polynomial and window size
// represented by table.
func newDigest(table *Table) *digest {
    d := new(digest)
    d.tab = table

    if table.window > 0 {
        // Leading zeros don't affect the hash, so we can
        // start with a full window of zeros and keep the
        // later logic simpler.
        d.msg = make([]byte, table.window)
    }

    return d
}

// Reset resets h to its initial state.
func (h *digest) Reset() {
    h.hash = 0
    if h.msg != nil {
        for i := range h.msg {
            h.msg[i] = 0
        }
        h.pos = 0
    }
}

// Size returns the number of bytes Sum will append. This is the
// minimum number of bytes necessary to represent the hash.
func (h *digest) Size() int {
    bits := h.tab.degree + 1
    return (bits + 7) / 8
}

// BlockSize returns the window size if a window is configured, and
// otherwise returns 1.
//
// This satisfies the hash.Hash interface and indicates that Write is
// most efficient if writes are a multiple of the returned size.
func (h *digest) BlockSize() int {
    if h.msg != nil {
        return len(h.msg)
    }

    return 1
}

// Write adds p to the running hash h.
//
// If h is windowed, this may also expire previously written bytes
// from the running hash so that h represents the hash of only the
// most recently written window bytes.
//
// It always returns len(p), nil.
func (h *digest) Write(p []byte) (n int, err error) {
    n = len(p)

    if h.msg == nil {
        h.hash = h.tab.update(h.hash, p)
        return
    }

    window := len(h.msg)
    if len(p) >= window {
        // p covers the entire window. Discard our entire
        // state and just hash the last window bytes of p.
        p = p[len(p)-window:]
        copy(h.msg, p)

        h.pos, h.hash = 0, 0
        h.hash = h.tab.update(h.hash, p)
        return
    }

    // Add and remove bytes as we overwrite them in the window.
    tab := h.tab
    pos, hash, shift := h.pos, h.hash, tab.shift%64
    for _, b := range p {
        pop := h.msg[pos]
        h.msg[pos] = b
        if pos++; pos == window {
            pos = 0
        }

        hash ^= tab.pop[pop]
        top := uint8(hash >> shift)
        hash = (hash<<8 | uint64(b)) ^ tab.push[top]
    }

    h.pos, h.hash = int(pos), hash
    return
}

// Sum appends the least-significant byte first representation of the
// current hash to b and returns the resulting slice.
func (h *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := h.copy()
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (h *digest) checkSum() []byte {
    var hbytes [8]byte
    for i := range hbytes {
        hbytes[i] = byte(h.hash >> uint(i*8))
    }

    return hbytes[:h.Size()]
}

// Sum64 returns the hash of all bytes written to h.
func (h *digest) Sum64() uint64 {
    return h.hash
}

func (h *digest) copy() *digest {
    table := *h.tab

    nd := &digest{
        tab:  &table,
        hash: h.hash,
        msg:  make([]byte, len(h.msg)),
        pos:  h.pos,
    }
    copy(nd.msg, h.msg)

    return nd
}
