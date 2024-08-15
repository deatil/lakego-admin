package memory

import (
    "reflect"
    "testing"
)

func TestFieldIsAligned(t *testing.T, align uintptr, raw interface{}, fieldName string) {
    v := reflect.ValueOf(raw)
    for v.Kind() == reflect.Ptr {
        v = v.Elem()
    }
    vt := v.Type()

    vtf, ok := vt.FieldByName(fieldName)
    if !ok {
        t.Errorf("%s.%s not found", vt.Name(), fieldName)
        return
    }

    if vtf.Offset&(align-1) != 0 {
        t.Errorf("%s.%s is not Aligned. offset=%d", vt.Name(), fieldName, vtf.Offset)
    }
}
