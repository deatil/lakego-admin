package x25

import (
    "fmt"
    "strings"
    "testing"
)

var tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "FA73"},
    {"dfg.;kp[jewijr0-34ls", "4938"},
    {"123123", "C56A"},
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
