package asn1

import "reflect"

var nullType = reflect.TypeOf(Null{})

type Null struct{}

type nullEncoder Null

func (b nullEncoder) length() int {
    return 1
}

func (e nullEncoder) encode() ([]byte, error) {
    return nil, nil
}

