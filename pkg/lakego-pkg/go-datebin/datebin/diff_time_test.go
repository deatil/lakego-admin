package datebin

import (
	"testing"
)

func Test_DiffTime_Set(t *testing.T) {
	eq := assertEqualT(t)

	start := "2024-06-06 21:15:12"
	end := "2024-07-05 21:15:12"

	startT := Parse(start)
	endT := Parse(end)

	dt := DiffTime{}
	dt = dt.SetStart(startT).SetEnd(endT)

	eq(dt.Start, startT, "failed DiffTime_Set Start")
	eq(dt.End, endT, "failed DiffTime_Set End")
}

func Test_DiffTime_Get(t *testing.T) {
	eq := assertEqualT(t)

	start := "2024-06-06 21:15:12"
	end := "2024-07-05 21:15:12"

	startT := Parse(start)
	endT := Parse(end)

	dt := DiffTime{
		Start: startT,
		End:   endT,
	}

	eq(dt.GetStart(), startT, "failed DiffTime_Get Start")
	eq(dt.GetEnd(), endT, "failed DiffTime_Get End")
}

func Test_NewDiffTime(t *testing.T) {
	eq := assertEqualT(t)

	start := "2024-06-06 21:15:12"
	end := "2024-07-05 21:15:12"

	startT := Parse(start)
	endT := Parse(end)

	dt := NewDiffTime(startT, endT)

	eq(dt.Start, startT, "failed NewDiffTime Start")
	eq(dt.End, endT, "failed NewDiffTime End")
}
