package modbus

import (
    "fmt"
    "strings"
    "testing"
)

var tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "381B"},
    {"dfg.;kp[jewijr0-34ls", "2D12"},
    {"123123", "36"},
}

func Test_CRC16(t *testing.T) {
    for index, test := range tests {
        crcData := Checksum(test.input)
        crcData = strings.ToUpper(crcData)

        t.Run(fmt.Sprintf("CRC16 %d", index), func(t *testing.T) {
            if test.output != crcData {
                t.Errorf("[%d] got %s, want %s", index, crcData, test.output)
            }
        })
    }
}
