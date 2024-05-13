package rabin

import (
    "io"
)

type errReadZero struct{}

func (e *errReadZero) Error() string {
    return "io.Reader returned 0 bytes and no error"
}

// A Discarder supports discarding bytes from an input stream.
type Discarder interface {
    // Discard skips the next n bytes, returning the number of
    // bytes discarded.
    //
    // If Discard skips fewer than n bytes, it also returns an
    // error. Discard must not skip beyond the end of the file.
    Discard(n int) (discarded int, err error)
}

// A Chunker performs content-defined chunking. It divides a sequence
// of bytes into chunks such that insertions and deletions in the
// sequence will only affect chunk boundaries near those
// modifications.
type Chunker struct {
    tab *Table
    r   io.Reader

    // buf is a buffer of data read from r. Its length is a power
    // of two.
    buf []byte

    // head is the number of bytes consumed from buf.
    // tail is the number of bytes read into buf.
    head, tail uint64

    // minBytes and maxBytes are the minimum and maximum chunk
    // size.
    minBytes, maxBytes uint64

    // hashMask is the average chunk size minus one. Chunk
    // boundaries occur where hash&hashMask == hashMask.
    hashMask uint64

    // ioErr is the sticky error returned from r.Read.
    ioErr error
}

// NewChunker returns a content-defined chunker for data read from r
// using the Rabin hash defined by table. The chunks produced by this
// Chunker will be at least minBytes and at most maxBytes large and
// will, on average, be avgBytes large.
//
// The Chunker buffers data from the Reader internally, so the Reader
// need not buffer itself. The caller may seek the reader, but if it
// does, it must only seek to a known chunk boundary and it must call
// Reset on the Chunker.
//
// If the Reader additionally implements Discarder, the Chunker will
// use this to skip over bytes more efficiently.
//
// The hash function defined by table must have a non-zero window
// size.
//
// minBytes must be >= the window size. This ensures that chunk
// boundary n+1 does not depend on data from before chunk boundary n.
//
// avgBytes must be a power of two.
func NewChunker(table *Table, r io.Reader, minBytes, avgBytes, maxBytes int) *Chunker {
    if table.window <= 0 {
        panic("Chunker requires a windowed hash function")
    }
    if table.window > minBytes {
        panic("minimum block size must be >= window size")
    }
    if maxBytes < minBytes {
        panic("maximum block size must be >= minimum block size")
    }
    if avgBytes&(avgBytes-1) != 0 {
        panic("average block size must be a power of two")
    }

    logBufSize := uint(10)
    for 1<<logBufSize < table.window*2 {
        // We use the buffer to store the window, so we need
        // at least enough space for that and for reading more
        // data.
        logBufSize++
    }
    buf := make([]byte, 1<<logBufSize)

    return &Chunker{
        tab: table, r: r, buf: buf,
        minBytes: uint64(minBytes), maxBytes: uint64(maxBytes),
        hashMask: uint64(avgBytes - 1),
    }
}

// Reset resets c and clears its internal buffer. The caller must
// ensure that the underlying Reader is at a chunk boundary when
// calling Reset.
//
// This is useful if the caller has knowledge of where an
// already-chunked stream is being modified. It can start at the chunk
// boundary before the modified point and re-chunk the stream until a
// new chunk boundary lines up with a boundary in the previous version
// of the stream.
func (c *Chunker) Reset() {
    c.head, c.tail = 0, 0
    c.ioErr = nil
}

// Next returns the length in bytes of the next chunk. If there are no
// more chunks, it returns 0, io.EOF. If the underlying Reader returns
// some other error, it passes that error on to the caller.
func (c *Chunker) Next() (int, error) {
    if c.ioErr != nil {
        return 0, c.ioErr
    }

    // The buffer head is at the first byte of this chunk. The
    // reader may be ahead of this.
    start := c.head
    tab := c.tab
    bufMask := uint64(len(c.buf) - 1)

    // Skip forward until we're one window short of the minimum
    // chunk size.
    window := uint64(tab.window)
    c.head += uint64(c.minBytes - window)
    if c.head > c.tail {
        if err := c.discard(int(c.head - c.tail)); err != nil {
            if err == io.EOF {
                // Return this chunk.
                return int(c.tail - start), nil
            }
            return 0, err
        }
    }

    // Prime the hash on the window leading up to the minimum
    // chunk size. Until we've covered the whole window, these
    // intermediate hash values don't mean anything, so we ignore
    // chunk boundaries.
    for c.tail < c.head+window {
        if err := c.more(); err != nil {
            if err == io.EOF && c.tail != start {
                // Return this chunk.
                return int(c.tail - start), nil
            }
            return 0, err
        }
    }
    b1, b2 := c.buf[c.head&bufMask:], []byte(nil)
    if uint64(len(b1)) >= window {
        b1 = b1[:window]
    } else {
        b2 = c.buf[:window-uint64(len(b1))]
    }
    hash := tab.update(tab.update(0, b1), b2)

    // At this point, c.head points to the *beginning* of the
    // window, so our hashing position is actually c.head+window.

    // Process bytes and roll the window looking for a hash
    // boundary.
    buf, head, hashMask := c.buf, c.head, c.hashMask
    shift := tab.shift % 64
    refill := c.tail - window
    limit := start + c.maxBytes - window
    for hash&hashMask != hashMask && head < limit {
        if head == refill {
            c.head = head
            if err := c.more(); err != nil {
                if err == io.EOF {
                    // Return this chunk.
                    break
                }
                return 0, err
            }
            refill = c.tail - window
        }
        pop := buf[head&bufMask]
        push := buf[(head+window)&bufMask]
        head++

        // Update the hash.
        hash ^= tab.pop[pop]
        top := uint8(hash >> shift)
        hash = (hash<<8 | uint64(push)) ^ tab.push[top]
    }
    // We found a chunk boundary. Shift c.head forward so it
    // points to the chunk boundary for the next call to Next.
    head += window
    // Flush state back.
    c.head = head

    // Return the size of the chunk.
    return int(head - start), nil
}

// discard discards the next n bytes from the Reader and updates
// c.tail. It may use any of c.buf as scratch space.
func (c *Chunker) discard(n int) error {
    if c.ioErr != nil {
        return c.ioErr
    }

    // If the Reader natively supports discarding, use it.
    // Unfortunately, io.Seeker isn't sufficient because it can
    // seek past the end of file and then we don't know how much
    // was actually available.
    if d, ok := c.r.(Discarder); ok {
        m, err := d.Discard(n)
        c.tail += uint64(m)
        c.ioErr = err
        return err
    }

    for n > 0 {
        scratch := c.buf
        if len(scratch) > n {
            scratch = scratch[:n]
        }
        m, err := c.r.Read(scratch)
        if m > 0 {
            n -= m
            c.tail += uint64(m)
        }
        if err != nil {
            c.ioErr = err
            return err
        }
    }
    return nil
}

// more retrieves more data into c.buf. It retrieves the minimum that
// is convenient, rather than attempting to fill c.buf.
func (c *Chunker) more() error {
    if c.ioErr != nil {
        return c.ioErr
    }

    var buf []byte
    bufMask := uint64(len(c.buf) - 1)
    if wtail, whead := c.tail&bufMask, c.head&bufMask; whead <= wtail {
        buf = c.buf[wtail:]
    } else {
        buf = c.buf[wtail:whead]
    }
    n, err := c.r.Read(buf)
    if n > 0 {
        c.tail += uint64(n)
        // If there was an error, return it on the next
        // invocation.
        c.ioErr = err
        return nil
    }
    if err == nil {
        // This could lead to infinite loops, so bail out
        // instead.
        err = &errReadZero{}
    }
    // Make the error sticky.
    c.ioErr = err
    return err
}
