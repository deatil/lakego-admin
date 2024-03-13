package randomart

import (
    "testing"
)

func Test_Randomart(t *testing.T) {
    str   := "123456789"

    res := Randomart(str)
    if len(res) == 0 {
        t.Error("Randomart error, got zero")
    }
}
