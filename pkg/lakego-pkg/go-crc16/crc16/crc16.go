package crc16

import "math/bits"

// 参数
type Params struct {
    Poly   uint16
    Init   uint16
    RefIn  bool
    RefOut bool
    XorOut uint16
    Name   string
}

// crc16 类型列表
var (
    CRC16_ARC         = Params{0x8005, 0x0000, true, true, 0x0000, "CRC-16/ARC"}
    CRC16_AUG_CCITT   = Params{0x1021, 0x1D0F, false, false, 0x0000, "CRC-16/AUG-CCITT"}
    CRC16_BUYPASS     = Params{0x8005, 0x0000, false, false, 0x0000, "CRC-16/BUYPASS"}
    CRC16_CCITT       = Params{0x1021, 0x0000, true, true, 0x0000, "CRC-16/CCITT"}
    CRC16_CCITT_FALSE = Params{0x1021, 0xFFFF, false, false, 0x0000, "CRC-16/CCITT-FALSE"}
    CRC16_CDMA2000    = Params{0xC867, 0xFFFF, false, false, 0x0000, "CRC-16/CDMA2000"}
    CRC16_DDS_110     = Params{0x8005, 0x800D, false, false, 0x0000, "CRC-16/DDS-110"}
    CRC16_DECT_R      = Params{0x0589, 0x0000, false, false, 0x0001, "CRC-16/DECT-R"}
    CRC16_DECT_X      = Params{0x0589, 0x0000, false, false, 0x0000, "CRC-16/DECT-X"}
    CRC16_DNP         = Params{0x3D65, 0x0000, true, true, 0xFFFF, "CRC-16/DNP"}
    CRC16_EN_13757    = Params{0x3D65, 0x0000, false, false, 0xFFFF, "CRC-16/EN-13757"}
    CRC16_GENIBUS     = Params{0x1021, 0xFFFF, false, false, 0xFFFF, "CRC-16/GENIBUS"}
    CRC16_MAXIM       = Params{0x8005, 0x0000, true, true, 0xFFFF, "CRC-16/MAXIM"}
    CRC16_MCRF4XX     = Params{0x1021, 0xFFFF, true, true, 0x0000, "CRC-16/MCRF4XX"}
    CRC16_RIELLO      = Params{0x1021, 0xB2AA, true, true, 0x0000, "CRC-16/RIELLO"}
    CRC16_T10_DIF     = Params{0x8BB7, 0x0000, false, false, 0x0000, "CRC-16/T10-DIF"}
    CRC16_TELEDISK    = Params{0xA097, 0x0000, false, false, 0x0000, "CRC-16/TELEDISK"}
    CRC16_TMS37157    = Params{0x1021, 0x89EC, true, true, 0x0000, "CRC-16/TMS37157"}
    CRC16_USB         = Params{0x8005, 0xFFFF, true, true, 0xFFFF, "CRC-16/USB"}
    CRC16_CRC_A       = Params{0x1021, 0xC6C6, true, true, 0x0000, "CRC-16/CRC-A"}
    CRC16_KERMIT      = Params{0x1021, 0x0000, true, true, 0x0000, "CRC-16/KERMIT"}
    CRC16_MODBUS      = Params{0x8005, 0xFFFF, true, true, 0x0000, "CRC-16/MODBUS"}
    CRC16_X_25        = Params{0x1021, 0xFFFF, true, true, 0xFFFF, "CRC-16/X-25"}
    CRC16_XMODEM      = Params{0x1021, 0x0000, false, false, 0x0000, "CRC-16/XMODEM"}
)

// 表格
type Table struct {
    params Params
    data   [256]uint16
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
func (this *Table) WithData(data [256]uint16) *Table {
    this.data = data

    return this
}

// 获取数据
func (this *Table) GetData() [256]uint16 {
    return this.data
}

// 生成数值
func (this *Table) MakeData() *Table {
    for n := 0; n < 256; n++ {
        crc := uint16(n) << 8

        for i := 0; i < 8; i++ {
            bit := (crc & 0x8000) != 0
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
func (this *Table) Init() uint16 {
    return this.params.Init
}

// 更新
func (this *Table) Update(crc uint16, data []byte) uint16 {
    for _, d := range data {
        if this.params.RefIn {
            d = bits.Reverse8(d)
        }

        crc = (crc << 8) ^ this.data[byte(crc>>8)^d]
    }

    return crc
}

// 完成
func (this *Table) Complete(crc uint16) uint16 {
    if this.params.RefOut {
        return bits.Reverse16(crc) ^ this.params.XorOut
    }

    return crc ^ this.params.XorOut
}

// Checksum
// LSB-MSB，即低字节在前
// Modbus，即高字节在前
func (this *Table) Checksum(data []byte) uint16 {
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
