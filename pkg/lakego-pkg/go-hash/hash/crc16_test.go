package hash

import (
    "fmt"
    "strings"
    "testing"
)

var crc16X25Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "FA73"},
    {"dfg.;kp[jewijr0-34ls", "4938"},
    {"123123", "C56A"},
}

func Test_CRC16_X25(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range crc16X25Tests {
        e := FromString(test.input).CRC16_X25()

        t.Run(fmt.Sprintf("CRC16_X25_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "CRC16_X25")

            crcData := LeftCRCPadding(strings.ToUpper(e.ToHexString()), 4)
            assert(test.output, crcData, "CRC16_X25")
        })
    }
}

// ====================

var crc16ModbusTests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "381B"},
    {"dfg.;kp[jewijr0-34ls", "2D12"},
    {"123123", "0036"},
}

func Test_CRC16_Modbus(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range crc16ModbusTests {
        e := FromString(test.input).CRC16_Modbus()

        t.Run(fmt.Sprintf("CRC16_Modbus_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "CRC16_Modbus")

            crcData := LeftCRCPadding(strings.ToUpper(e.ToHexString()), 4)
            assert(test.output, crcData, "CRC16_Modbus")
        })
    }
}
