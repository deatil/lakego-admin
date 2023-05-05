package encode

import (
    "reflect"
    "time"
)

var (
    timeType = reflect.TypeOf(time.Time{})
)

func encodeUTCTime(value reflect.Value) ([]byte, error) {
    if value.Type() != timeType {
        return nil, invalidTypeError("time.Time", value)
    }
    t := value.Interface().(time.Time)
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
    utcTime := t.UTC().Format("060102150405Z")
    return []byte(utcTime), nil
}

func encodeGeneralizedTime(value reflect.Value) ([]byte, error) {
    if value.Type() != timeType {
        return nil, invalidTypeError("time.Time", value)
    }
    t := value.Interface().(time.Time)
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2
    generalizedTime := t.UTC().Format("20060102150405Z")
    return []byte(generalizedTime), nil
}
