package test

import (
    "errors"
    "testing"
)

func Test_AssertEqualT(t *testing.T) {
    {
        mockT := new(testing.T)

        eq := AssertEqualT(mockT)
        eq("asd", "ert", "eq fail")

        if !mockT.Failed() {
            t.Error("AssertEqualT should is Failed")
        }
    }

    {
        mockT := new(testing.T)

        eq := AssertEqualT(mockT)
        eq("asd", "asd", "eq fail")

        if mockT.Failed() {
            t.Error("AssertEqualT should is not Failed")
        }
    }
}

func Test_AssertNotEqualT(t *testing.T) {
    {
        mockT := new(testing.T)

        noteq := AssertNotEqualT(mockT)
        noteq("asd", "ert", "eq fail")

        if mockT.Failed() {
            t.Error("AssertNotEqualT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        noteq := AssertNotEqualT(mockT)
        noteq("asd", "asd", "eq fail")

        if !mockT.Failed() {
            t.Error("AssertNotEqualT should is Failed")
        }
    }

}

func Test_AssertErrorT(t *testing.T) {
    {
        mockT := new(testing.T)

        err := AssertErrorT(mockT)

        err2 := errors.New("test error")
        err(err2, "AssertErrorT fail")

        if mockT.Failed() {
            t.Error("AssertErrorT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        err := AssertErrorT(mockT)

        var err2 error
        err(err2, "AssertErrorT fail")

        if !mockT.Failed() {
            t.Error("AssertErrorT should is Failed")
        }
    }

}

func Test_AssertNoErrorT(t *testing.T) {
    {
        mockT := new(testing.T)

        noerr := AssertNoErrorT(mockT)

        err2 := errors.New("test error")
        noerr(err2, "AssertNoErrorT fail")

        if !mockT.Failed() {
            t.Error("AssertNoErrorT should is Failed")
        }
    }

    {
        mockT := new(testing.T)

        noerr := AssertNoErrorT(mockT)

        var err2 error
        noerr(err2, "AssertNoErrorT fail")

        if mockT.Failed() {
            t.Error("AssertNoErrorT should is not Failed")
        }
    }

}

func Test_AssertEmptyT(t *testing.T) {
    {
        mockT := new(testing.T)

        empty := AssertEmptyT(mockT)

        data := ""
        empty(data, "AssertEmptyT fail")

        if mockT.Failed() {
            t.Error("AssertEmptyT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        empty := AssertEmptyT(mockT)

        data := "test error"
        empty(data, "AssertEmptyT fail")

        if !mockT.Failed() {
            t.Error("AssertEmptyT should is Failed")
        }
    }

}

func Test_AssertNotEmptyT(t *testing.T) {
    {
        mockT := new(testing.T)

        notempty := AssertNotEmptyT(mockT)

        data := "test error"
        notempty(data, "AssertNotEmptyT fail")

        if mockT.Failed() {
            t.Error("AssertNotEmptyT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        notempty := AssertNotEmptyT(mockT)

        data := ""
        notempty(data, "AssertNotEmptyT fail")

        if !mockT.Failed() {
            t.Error("AssertNotEmptyT should is Failed")
        }
    }

}

func Test_AssertTrueT(t *testing.T) {
    {
        mockT := new(testing.T)

        True := AssertTrueT(mockT)

        data := true
        True(data, "AssertTrueT fail")

        if mockT.Failed() {
            t.Error("AssertTrueT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        True := AssertTrueT(mockT)

        data := false
        True(data, "AssertTrueT fail")

        if !mockT.Failed() {
            t.Error("AssertTrueT should is Failed")
        }
    }

}

func Test_AssertFalseT(t *testing.T) {
    {
        mockT := new(testing.T)

        False := AssertFalseT(mockT)

        data := false
        False(data, "AssertFalseT fail")

        if mockT.Failed() {
            t.Error("AssertFalseT should is not Failed")
        }
    }

    {
        mockT := new(testing.T)

        False := AssertFalseT(mockT)

        data := true
        False(data, "AssertFalseT fail")

        if !mockT.Failed() {
            t.Error("AssertFalseT should is Failed")
        }
    }

}
