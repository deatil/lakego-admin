package crc8

import "math/bits"

// 参数
type Params struct {
    Poly   uint8
    Init   uint8
    RefIn  bool
    RefOut bool
    XorOut uint8
    Name   string
}

// crc8 类型列表
var (
    CRC8          = Params{0x07, 0x00, false, false, 0x00, "CRC-8"}
    CRC8_CDMA2000 = Params{0x9B, 0xFF, false, false, 0x00, "CRC-8/CDMA2000"}
    CRC8_DARC     = Params{0x39, 0x00, true, true, 0x00, "CRC-8/DARC"}
    CRC8_DVB_S2   = Params{0xD5, 0x00, false, false, 0x00, "CRC-8/DVB-S2"}
    CRC8_EBU      = Params{0x1D, 0xFF, true, true, 0x00, "CRC-8/EBU"}
    CRC8_I_CODE   = Params{0x1D, 0xFD, false, false, 0x00, "CRC-8/I-CODE"}
    CRC8_ITU      = Params{0x07, 0x00, false, false, 0x55, "CRC-8/ITU"}
    CRC8_MAXIM    = Params{0x31, 0x00, true, true, 0x00, "CRC-8/MAXIM"}
    CRC8_ROHC     = Params{0x07, 0xFF, true, true, 0x00, "CRC-8/ROHC"}
    CRC8_WCDMA    = Params{0x9B, 0x00, true, true, 0x00, "CRC-8/WCDMA"}
)

// 表格
type Table struct {
    params Params
    data   [256]uint8
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
func (this *Table) WithData(data [256]uint8) *Table {
    this.data = data

    return this
}

// 获取数据
func (this *Table) GetData() [256]uint8 {
    return this.data
}

// 生成数值
func (this *Table) MakeData() *Table {
    for n := 0; n < 256; n++ {
        crc := uint8(n)
        for i := 0; i < 8; i++ {
            bit := (crc & 0x80) != 0
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
func (this *Table) Init() uint8 {
    return this.params.Init
}

// 更新
func (this *Table) Update(crc uint8, data []byte) uint8 {
    if this.params.RefIn {
        for _, d := range data {
            d = bits.Reverse8(d)
            crc = this.data[crc^d]
        }
    } else {
        for _, d := range data {
            crc = this.data[crc^d]
        }
    }

    return crc
}

// 完成
func (this *Table) Complete(crc uint8) uint8 {
    if this.params.RefOut {
        crc = bits.Reverse8(crc)
    }

    return crc ^ this.params.XorOut
}

// Checksum
func (this *Table) Checksum(data []byte) uint8 {
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
