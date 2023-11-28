package loki97

import (
    "bytes"
    "testing"
    "math/rand"
)

func TestULONG64(t *testing.T) {
    random := rand.New(rand.NewSource(99))

    key := make([]byte, 8)
    random.Read(key)

    en := byteToULONG64(key)
    de := ULONG64ToBYTE(en)

    if !bytes.Equal(de[:], key[:]) {
        t.Errorf("byteToULONG64/ULONG64ToBYTE failed: % 02x != % 02x\n", de, key)
    }
}
