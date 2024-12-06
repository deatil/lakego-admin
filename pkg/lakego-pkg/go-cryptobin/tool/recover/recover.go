package recover

import (
    "fmt"
    "errors"
)

// recover and return error when throw panic
func Recover(fn func()) (err error) {
    defer func() {
        if e := recover(); e != nil {
            err = errors.New(fmt.Sprintf("%v", e))
        }
    }()

    fn()

    return
}
