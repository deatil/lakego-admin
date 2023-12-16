package crc32

import "math/bits"

// 参数
// NAME：参数模型名称。
// WIDTH：宽度，即CRC比特数。位数为：32
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

// 类型列表
var (
    // "CRC-32" x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
    CRC32        = Params{0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF}
    // "CRC-32/MPEG-2" x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
    CRC32_MPEG_2 = Params{0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000}
    // "CRC-32/BZIP2" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_BZIP2  = Params{0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF}
    // "CRC-32/POSIX" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_POSIX  = Params{0x04C11DB7, 0x00000000, false, false, 0xFFFFFFFF}
    // "CRC-32/CKSUM" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_CKSUM  = CRC32_POSIX
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

    // "CRC-32/XFER" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_XFER   = Params{0x000000AF, 0x00000000, false, false, 0x00000000}
    // "CRC-32/CRC32Q" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_CRC32Q = Params{0x814141AB, 0x00000000, false, false, 0x00000000}
    // "CRC-32/CRC32D" x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
    CRC32_CRC32D = Params{0xA833982B, 0xFFFFFFFF, true, true, 0xFFFFFFFF}

    // "CRC-32/CDMA"
    CRC30_CDMA     = Params{0X2030B9C7, 0X3FFFFFFF, false, false, 0X3FFFFFFF}
    CRC31_Philips  = Params{0X04C11DB7, 0X7FFFFFFF, false, false, 0X7FFFFFFF}
    CRC32_AIXM     = Params{0X814141AB, 0X00000000, false, false, 0X00000000}
    CRC32_Autosar  = Params{0XF4ACFB13, 0XFFFFFFFF, true, true, 0XFFFFFFFF}
    CRC32_Base91D  = Params{0XA833982B, 0XFFFFFFFF, true, true, 0XFFFFFFFF}
    CRC32_CdRomEdc = Params{0X8001801B, 0X00000000, true, true, 0X00000000}
    CRC32_ISCSI    = Params{0X1EDC6F41, 0XFFFFFFFF, true, true, 0XFFFFFFFF}
    CRC32_IsoHdlc  = Params{0X04C11DB7, 0XFFFFFFFF, true, true, 0XFFFFFFFF}
    CRC32_MEF      = Params{0X741B8CD7, 0XFFFFFFFF, true, true, 0X00000000}
)

// 表格
type CRC struct {
    params Params
    table  [256]uint32
}

// 设置参数
func (this *CRC) WithParams(params Params) *CRC {
    this.params = params

    return this
}

// 获取参数
func (this *CRC) GetParams() Params {
    return this.params
}

// 设置数据
func (this *CRC) WithTable(table [256]uint32) *CRC {
    this.table = table

    return this
}

// 获取数据
func (this *CRC) GetTable() [256]uint32 {
    return this.table
}

// 生成数值
func (this *CRC) MakeTable() *CRC {
    for n := 0; n < 256; n++ {
        crc := uint32(n) << 24

        for i := 0; i < 8; i++ {
            bit := (crc & 0x80000000) != 0
            crc <<= 1
            if bit {
                crc ^= this.params.Poly
            }
        }

        this.table[n] = crc
    }

    return this
}

// 初始值
func (this *CRC) Init() uint32 {
    return this.params.Init
}

// 更新
func (this *CRC) Update(crc uint32, data []byte) uint32 {
    for _, d := range data {
        if this.params.RefIn {
            d = bits.Reverse8(d)
        }

        crc = (crc << 8) ^ this.table[byte(crc >> 24) ^ d]
    }

    return crc
}

// 完成
func (this *CRC) Complete(crc uint32) uint32 {
    if this.params.RefOut {
        return bits.Reverse32(crc) ^ this.params.XorOut
    }

    return crc ^ this.params.XorOut
}

// Checksum
// LSB-MSB，即低字节在前
// Modbus，即高字节在前
func (this *CRC) Checksum(data []byte) uint32 {
    crc := this.MakeTable().Init()
    crc = this.Update(crc, data)

    return this.Complete(crc)
}

// 构造函数
func NewCRC(params ...Params) *CRC {
    crc := &CRC{}

    if len(params) > 0 {
        crc.WithParams(params[0])
    }

    return crc
}
