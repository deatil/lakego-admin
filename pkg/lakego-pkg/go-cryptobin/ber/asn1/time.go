package asn1

import (
    "reflect"
    "time"
)

var timeType = reflect.TypeOf(time.Time{})

func makeUTCTime(t time.Time) string {
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
    return time.Time(t).Format("060102150405-0700")
}

func makeGeneralizedTime(t time.Time) string {
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2
    return time.Time(t).Format("20060102150405Z")
}
