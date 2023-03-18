package hash

import (
    "hash/crc32"
)

// CRC32IEEE 哈希值
func (this Hash) CRC32_IEEE() Hash {
    h := crc32.NewIEEE()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewCRC32_IEEE
func (this Hash) NewCRC32_IEEE() Hash {
    this.hash = crc32.NewIEEE()

    return this
}

// ============================================

// CRC32Castagnoli 哈希值
func (this Hash) CRC32_Castagnoli() Hash {
    tab := crc32.MakeTable(crc32.Castagnoli)

    h := crc32.New(tab)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewCRC32_Castagnoli
func (this Hash) NewCRC32_Castagnoli() Hash {
    tab := crc32.MakeTable(crc32.Castagnoli)

    this.hash = crc32.New(tab)

    return this
}

// ============================================

// CRC32Koopman 哈希值
func (this Hash) CRC32_Koopman() Hash {
    tab := crc32.MakeTable(crc32.Koopman)

    h := crc32.New(tab)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewCRC32_Koopman
func (this Hash) NewCRC32_Koopman() Hash {
    tab := crc32.MakeTable(crc32.Koopman)

    this.hash = crc32.New(tab)

    return this
}
