package expect

import (
    "fmt"
    "reflect"
    "database/sql"
)

func Nil(x any) {
    if x != nil {
        panic(fmt.Sprintf("expected nil; got %v", x))
    }
}

func NotNil(x any) {
    if x == nil {
        panic(x)
    }
}

func Equal(x, y any) {
    if x == y {
        return
    }

    yAsXType := reflect.ValueOf(y).Convert(reflect.TypeOf(x)).Interface()
    if !reflect.DeepEqual(x, yAsXType) {
        panic(fmt.Sprintf("%v != %v", x, y))
    }
}

func StrictlyEqual(x, y any) {
    if x != y {
        panic(fmt.Sprintf("%s != %s", x, y))
    }
}

func OneRowAffected(r sql.Result) {
    count, err := r.RowsAffected()
    Nil(err)
    if count != 1 {
        panic(count)
    }
}

var Ok = True

func True(b bool) {
    if !b {
        panic(b)
    }
}

func False(b bool) {
    if b {
        panic(b)
    }
}

func Zero(x any) {
    if x != reflect.Zero(reflect.TypeOf(x)).Interface() {
        panic(x)
    }
}
