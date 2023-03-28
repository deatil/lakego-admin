package url

import (
    "testing"
    "reflect"
)

func assertT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func assertBoolT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        if !data {
            t.Errorf("Failed %s: error: %+v", msg, data)
        }
    }
}

func assertEmptyT(t *testing.T) func(string, string) {
    return func(data string, msg string) {
        if data == "" {
            t.Errorf("Failed %s: error: data empty", msg)
        }
    }
}

// Test_URL
func Test_URL(t *testing.T) {
    assert := assertT(t)
    assertEmpty := assertEmptyT(t)

    url := "github.com/deatil/lakego-admin"

    u := ParseURL(url)
    u.AddQuery("a", "aaa")
    u.AddQuery("b", "bbb")
    res := u.BuildString()

    assert(res, url + "?a=aaa&b=bbb", "Test_URL")
    assertEmpty(res, "Test_URL")
}

// Test_Matcher
func Test_Matcher(t *testing.T) {
    assertBool := assertBoolT(t)

    url := "github.com/deatil/lakego-admin/data/aaaa/bbbb/cccc?q=backe"

    m := NewMatcher()
    assertBool(m.Match("github.com/deatil/lakego-admin/data/**", url), "Test_Matcher_Match")
    assertBool(m.Match("github.com/deatil/lakego-admin/data/*/bbbb/cccc?q=backe", url), "Test_Matcher_Match")
    assertBool(m.IsPattern(url), "Test_Matcher_IsPattern")
}
