package crc32

import "math/bits"

// 参数
// NAME：参数模型名称。
// WIDTH：宽度，即CRC比特数。位数为：16
type Params struct {
    // 生成项的简写，以16进制表示。
    // 例如：CRC-32 即是0x04C11DB7，
    // 忽略了最高位的"1"，即完整的生成项是0x104C11DB7。
    Poly   uint32

    // 这是算法开始时寄存器（crc）的初始化预置值，十六进制表示。
    Init   uint32

    // 待测数据的每个字节是否按位反转，True或False。
    RefIn  bool

    // 在计算后之后，异或输出之前，整个数据是否按位反转，True或False。
    RefOut bool

    // 计算结果与此参数异或后得到最终的CRC值。
    XorOut uint32
}

// crc16 类型列表
var (
    // "CRC-32" x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
    CRC32        = Params{0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF}
    // "CRC-32/MPEG-2" x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
    CRC32_MPEG_2 = Params{0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000}
    // "CRC-32/BZIP2" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_BZIP2  = Params{0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF}
    // "CRC-32/POSIX" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_POSIX  = Params{0x04C11DB7, 0x00000000, false, false, 0xFFFFFFFF}
    // "CRC-32/JAMCRC" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_JAMCRC = Params{0x04C11DB7, 0xFFFFFFFF, true, true, 0x00000000}
    // "CRC-32/CRC32A" (ITU I.363.5 algorithm, popularized by BZIP2) checksum.
    // X32+X26+X23+X22+X16+X12+X11+X10+X8+X7+X5+X4+X2+X+1
    CRC32_CRC32A = CRC32_BZIP2

    // "CRC-32/IEEE" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_IEEE       = CRC32
    // "CRC-32/Castagnoli" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_Castagnoli = Params{0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF}
    // "CRC-32/CRC32C" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_CRC32C     = CRC32_Castagnoli
    // "CRC-32/Koopman" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_Koopman    = Params{0x741B8CD7, 0xFFFFFFFF, true, true, 0xFFFFFFFF}
)

// 表格
type Table struct {
    params Params
    data   [256]uint32
}

// 设置参数
func (this *Table) WithParams(params Params) *Table {
    this.params = params

    return this
}

// 获取参数
func (this *Table) GetParams() Params {
    return this.params
}

// 设置数据
func (this *Table) WithData(data [256]uint32) *Table {
    this.data = data

    return this
}

// 获取数据
func (this *Table) GetData() [256]uint32 {
    return this.data
}

// 生成数值
func (this *Table) MakeData() *Table {
    for n := 0; n < 256; n++ {
        crc := uint32(n) << 24

        for i := 0; i < 8; i++ {
            bit := (crc & 0x80000000) != 0
            crc <<= 1
            if bit {
                crc ^= this.params.Poly
            }
        }

        this.data[n] = crc
    }

    return this
}

// 初始值
func (this *Table) Init() uint32 {
    return this.params.Init
}

// 更新
func (this *Table) Update(crc uint32, data []byte) uint32 {
    for _, d := range data {
        if this.params.RefIn {
            d = bits.Reverse8(d)
        }

        crc = (crc << 8) ^ this.data[byte(crc >> 24) ^ d]
    }

    return crc
}

// 完成
func (this *Table) Complete(crc uint32) uint32 {
    if this.params.RefOut {
        return bits.Reverse32(crc) ^ this.params.XorOut
    }

    return crc ^ this.params.XorOut
}

// Checksum
// LSB-MSB，即低字节在前
// Modbus，即高字节在前
func (this *Table) Checksum(data []byte) uint32 {
    crc := this.MakeData().Init()
    crc = this.Update(crc, data)

    return this.Complete(crc)
}

// 构造函数
func NewTable(params ...Params) *Table {
    table := &Table{}

    if len(params) > 0 {
        table.WithParams(params[0])
    }

    return table
}
