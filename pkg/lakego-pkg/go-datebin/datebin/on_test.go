package datebin

import (
	"errors"
	"testing"
)

func Test_OnError(t *testing.T) {
	eq := assertEqualT(t)

	errs := []error{
		errors.New("test error"),
		errors.New("test error22222"),
	}

	NewDatebin().
		AppendError(errs...).
		OnError(func(ers []error) {
			eq(ers, errs, "failed OnError")
		})
}
