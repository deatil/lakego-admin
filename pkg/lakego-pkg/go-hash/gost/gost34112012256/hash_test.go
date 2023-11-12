package gost34112012256

import (
    "hash"
    "testing"
    "encoding/binary"
)

func TestHashInterface(t *testing.T) {
    h := New()
    var _ hash.Hash = h
}

func TestHashed(t *testing.T) {
    h := New()
    m := make([]byte, BlockSize)
    for i := 0; i < BlockSize; i++ {
        m[i] = byte(i)
    }

    h.Write(m)
    hashed := h.Sum(nil)

    if len(hashed) == 0 {
        t.Error("Hash error")
    }
}

func Test_ESPTree(t *testing.T) {
    data := NewESPTree([]byte("rgtf5yds")).Derive([]byte("olkpj"))

    if len(data) == 0 {
        t.Error("ESPTree data error")
    }
}

func Test_TLSTree(t *testing.T) {
    num := binary.BigEndian.Uint64([]byte{0xFE, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00})

    data := NewTLSTree(TLSKuznyechikCTROMAC, []byte("rgtf5yds")).Derive(num)

    if len(data) == 0 {
        t.Error("TLSTree data error")
    }
}
