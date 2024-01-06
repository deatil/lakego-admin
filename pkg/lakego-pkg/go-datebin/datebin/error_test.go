package datebin

import (
    "errors"
    "testing"
)

func Test_Error(t *testing.T) {
    eq := assertEqualT(t)

    errs := []error{
        errors.New("test error"),
        errors.New("test error22222"),
    }
    check := "test error\ntest error22222"

    d := NewDatebin().AppendError(errs...)

    eq(d.Error().Error(), check, "failed Error")
}
