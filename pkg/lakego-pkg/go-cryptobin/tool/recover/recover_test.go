package recover

import (
    "errors"
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Recover(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    err := Recover(func() {
        panic("test panic")
    })

    assertError(err, "Test_Recover-assertError")
    assertEqual(err, errors.New("test panic"), "Test_Recover-assertEqual")
}
