package crc12

import "math/bits"

// 参数
// NAME：参数模型名称。
// WIDTH：宽度，即CRC比特数
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
    // "CRC-12"
    CRC12 = Params{0x180D, 0x0000, false, false, 0x0000}
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
        crc := uint16(n) << 4

        for i := 0; i < 8; i++ {
            bit := (crc & 0x800) != 0
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

        crc = (crc << 8) ^ this.table[byte(crc >> 4) ^ d]
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
