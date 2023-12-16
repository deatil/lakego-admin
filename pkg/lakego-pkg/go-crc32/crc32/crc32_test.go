package crc32

import (
    "testing"
)

func Test_CRC32_AIXM(t *testing.T) {
    data := "hjfiusdfj8o"

    sum := Checksum([]byte(data), CRC32_AIXM)
    if sum == 0 {
        t.Errorf("Checksum error, got %d", sum)
    }
}
