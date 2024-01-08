package datebin

import (
	"testing"
)

func Test_absFormat(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		data  int64
		check int64
	}{
		{
			index: "index-1",
			data:  25,
			check: 25,
		},
		{
			index: "index-2",
			data:  -25,
			check: 25,
		},
		{
			index: "index-3",
			data:  0,
			check: 0,
		},
	}

	for _, td := range tests {
		check := absFormat(td.data)

		eq(check, td.check, "failed absFormat, index "+td.index)
	}
}
