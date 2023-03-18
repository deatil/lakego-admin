package hash

import (
    "hash/crc64"
)

// CRC64ISO
func (this Hash) CRC64_ISO() Hash {
    tab := crc64.MakeTable(crc64.ISO)

    h := crc64.New(tab)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewCRC64_ISO
func (this Hash) NewCRC64_ISO() Hash {
    tab := crc64.MakeTable(crc64.ISO)

    this.hash = crc64.New(tab)

    return this
}

// ============================================

// CRC64ECMA 哈希值
func (this Hash) CRC64_ECMA() Hash {
    tab := crc64.MakeTable(crc64.ECMA)

    h := crc64.New(tab)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewCRC64_ECMA
func (this Hash) NewCRC64_ECMA() Hash {
    tab := crc64.MakeTable(crc64.ECMA)

    this.hash = crc64.New(tab)

    return this
}
