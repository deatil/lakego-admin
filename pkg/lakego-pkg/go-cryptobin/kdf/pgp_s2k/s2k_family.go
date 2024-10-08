package pgp_s2k

import (
    "time"
    "hash"
)

func tune(h hash.Hash, keylen int, msec time.Duration, _ int, tune_time time.Duration) int {
    var bufSize int = 1024
    var buffer = make([]byte, bufSize)
    var timeUsed uint64 = 0
    var eventCount uint64 = 0

    td := time.Duration(bufSize)

    timer := time.NewTimer(td)
    for {
        select {
            case <-timer.C:
                eventCount++
                timeUsed = timeUsed + uint64(td)

                h.Write(buffer)

                if time.Duration(timeUsed) < tune_time {
                    timer.Reset(td)
                }
        }
    }

    var hashBytesPerSecond uint64
    if td.Seconds() > 0 {
        hashBytesPerSecond = (uint64(bufSize) * eventCount) / uint64(td.Seconds())
    } else {
        hashBytesPerSecond = 0
    }

    desiredNsec := uint64(msec.Nanoseconds())

    hashSize := h.Size()

    var blocks_required int
    if keylen <= hashSize {
        blocks_required = 1
    } else {
        blocks_required = (keylen + hashSize - 1) / hashSize
    }

    bytesToBeHashed := (hashBytesPerSecond * (desiredNsec / 1000000000)) / uint64(blocks_required)
    iterations := roundIterations(uint32(bytesToBeHashed))

    return int(iterations)
}
