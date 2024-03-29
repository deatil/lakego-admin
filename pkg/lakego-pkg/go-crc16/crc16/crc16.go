package crc16

import "math/bits"

// 参数
// NAME：参数模型名称。
// WIDTH：宽度，即CRC比特数。位数为：16
type Params struct {
    // 生成项的简写，以16进制表示。
    // 例如：CRC-32 即是0x04C11DB7，
    // 忽略了最高位的"1"，即完整的生成项是0x104C11DB7。
    Poly   uint16

    // 这是算法开始时寄存器（crc）的初始化预置值，十六进制表示。
    Init   uint16

    // 待测数据的每个字节是否按位反转，True或False。
    RefIn  bool

    // 在计算后之后，异或输出之前，整个数据是否按位反转，True或False。
    RefOut bool

    // 计算结果与此参数异或后得到最终的CRC值。
    XorOut uint16
}

// 类型列表
var (
    // "CRC-16/IBM" x16 + x15 + x2 + 1
    CRC16_IBM         = Params{0x8005, 0x0000, true, true, 0x0000}
    // "CRC-16/ARC"
    CRC16_ARC         = Params{0x8005, 0x0000, true, true, 0x0000}
    // "CRC-16/AUG-CCITT"
    CRC16_AUG_CCITT   = Params{0x1021, 0x1D0F, false, false, 0x0000}
    // "CRC-16/BUYPASS"
    CRC16_BUYPASS     = Params{0x8005, 0x0000, false, false, 0x0000}
    // "CRC-16/CCITT" x16 + x15 + x2 + 1
    CRC16_CCITT       = Params{0x1021, 0x0000, true, true, 0x0000}
    // "CRC-16/CCITT-FALSE" x16 + x15 + x2 + 1
    CRC16_CCITT_FALSE = Params{0x1021, 0xFFFF, false, false, 0x0000}
    // "CRC-16/CDMA2000"
    CRC16_CDMA2000    = Params{0xC867, 0xFFFF, false, false, 0x0000}
    // "CRC-16/DDS-110"
    CRC16_DDS_110     = Params{0x8005, 0x800D, false, false, 0x0000}
    // "CRC-16/DECT-R"
    CRC16_DECT_R      = Params{0x0589, 0x0000, false, false, 0x0001}
    // "CRC-16/DECT-X"
    CRC16_DECT_X      = Params{0x0589, 0x0000, false, false, 0x0000}
    // "CRC-16/DNP" x16 + x13 + x12 + x11 + x10 + x8 + x6 + x5 + x2 + 1
    CRC16_DNP         = Params{0x3D65, 0x0000, true, true, 0xFFFF}
    // "CRC-16/EN-13757"
    CRC16_EN_13757    = Params{0x3D65, 0x0000, false, false, 0xFFFF}
    // "CRC-16/GENIBUS"
    CRC16_GENIBUS     = Params{0x1021, 0xFFFF, false, false, 0xFFFF}
    // "CRC-16/MAXIM" x16 + x15 + x2 + 1
    CRC16_MAXIM       = Params{0x8005, 0x0000, true, true, 0xFFFF}
    // "CRC-16/MCRF4XX"
    CRC16_MCRF4XX     = Params{0x1021, 0xFFFF, true, true, 0x0000}
    // "CRC-16/RIELLO"
    CRC16_RIELLO      = Params{0x1021, 0xB2AA, true, true, 0x0000}
    // "CRC-16/T10-DIF"
    CRC16_T10_DIF     = Params{0x8BB7, 0x0000, false, false, 0x0000}
    // "CRC-16/TELEDISK"
    CRC16_TELEDISK    = Params{0xA097, 0x0000, false, false, 0x0000}
    // "CRC-16/TMS37157"
    CRC16_TMS37157    = Params{0x1021, 0x89EC, true, true, 0x0000}
    // "CRC-16/USB" x16 + x15 + x2 + 1
    CRC16_USB         = Params{0x8005, 0xFFFF, true, true, 0xFFFF}
    // "CRC-16/CRC-A"
    CRC16_CRC_A       = Params{0x1021, 0xC6C6, true, true, 0x0000}
    // "CRC-16/KERMIT"
    CRC16_KERMIT      = Params{0x1021, 0x0000, true, true, 0x0000}
    // "CRC-16/MODBUS" x16 + x15 + x2 + 1
    CRC16_MODBUS      = Params{0x8005, 0xFFFF, true, true, 0x0000}
    // "CRC-16/X-25" x16 + x15 + x2 + 1
    CRC16_X_25        = Params{0x1021, 0xFFFF, true, true, 0xFFFF}
    // "CRC-16/XMODEM" x16 + x15 + x2 + 1
    CRC16_XMODEM      = Params{0x1021, 0x0000, false, false, 0x0000}
    // "CRC-16/XMODEM2" x16 + x15 + x2 + 1
    CRC16_XMODEM2     = Params{0x8408, 0x0000, true, true, 0x0000}
)

// 表格
type CRC struct {
    params Params
    table  [256]uint16
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
func (this *CRC) WithTable(table [256]uint16) *CRC {
    this.table = table

    return this
}

// 获取数据
func (this *CRC) GetTable() [256]uint16 {
    return this.table
}

// 生成数值
func (this *CRC) MakeTable() *CRC {
    for n := 0; n < 256; n++ {
        crc := uint16(n) << 8

        for i := 0; i < 8; i++ {
            bit := (crc & 0x8000) != 0
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
func (this *CRC) Init() uint16 {
    return this.params.Init
}

// 更新
func (this *CRC) Update(crc uint16, data []byte) uint16 {
    for _, d := range data {
        if this.params.RefIn {
            d = bits.Reverse8(d)
        }

        crc = (crc << 8) ^ this.table[byte(crc >> 8) ^ d]
    }

    return crc
}

// 完成
func (this *CRC) Complete(crc uint16) uint16 {
    if this.params.RefOut {
        return bits.Reverse16(crc) ^ this.params.XorOut
    }

    return crc ^ this.params.XorOut
}

// Checksum
// LSB-MSB，即低字节在前
// Modbus，即高字节在前
func (this *CRC) Checksum(data []byte) uint16 {
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
