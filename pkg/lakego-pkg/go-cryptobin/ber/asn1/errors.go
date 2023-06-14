package asn1

import (
    "fmt"
    "reflect"
)

type UnsupportedTypeError struct {
    Type reflect.Type
}

func (e *UnsupportedTypeError) Error() string {
    return fmt.Sprintf("asn1: unsupported type: %s", e.Type.String())
}

// A SyntaxError suggests that the ASN.1 data is invalid.
type SyntaxError struct {
    Msg string
}

func (e SyntaxError) Error() string {
    return "asn1: syntax error: " + e.Msg
}

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match.
type StructuralError struct {
    Msg string
}

func (e StructuralError) Error() string {
    return "asn1: structure error: " + e.Msg
}
