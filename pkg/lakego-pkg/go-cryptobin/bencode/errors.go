package bencode

import (
    "fmt"
    "reflect"
)

// In case if marshaler cannot encode a type, it will return this error. Typical
// example of such type is float32/float64 which has no bencode representation.
type MarshalTypeError struct {
    Type reflect.Type
}

func (e *MarshalTypeError) Error() string {
    return "bencode: unsupported type: " + e.Type.String()
}

// Unmarshal argument must be a non-nil value of some pointer type.
type UnmarshalInvalidArgError struct {
    Type reflect.Type
}

func (e *UnmarshalInvalidArgError) Error() string {
    if e.Type == nil {
        return "bencode: Unmarshal(nil)"
    }

    if e.Type.Kind() != reflect.Ptr {
        return "bencode: Unmarshal(non-pointer " + e.Type.String() + ")"
    }

    return "bencode: Unmarshal(nil " + e.Type.String() + ")"
}

// Unmarshaler spotted a value that was not appropriate for a given Go value.
type UnmarshalTypeError struct {
    BencodeTypeName     string
    UnmarshalTargetType reflect.Type
}

// This could probably be a value type, but we may already have users assuming
// that it's passed by pointer.
func (e *UnmarshalTypeError) Error() string {
    return fmt.Sprintf(
        "can't unmarshal a bencode %v into a %v",
        e.BencodeTypeName,
        e.UnmarshalTargetType,
    )
}

// Unmarshaler tried to write to an unexported (therefore unwritable) field.
type UnmarshalFieldError struct {
    Key   string
    Type  reflect.Type
    Field reflect.StructField
}

func (e *UnmarshalFieldError) Error() string {
    return "bencode: key \"" + e.Key +
        "\" led to an unexported field \"" +
        e.Field.Name + "\" in type: " + e.Type.String()
}

// Malformed bencode input, unmarshaler failed to parse it.
type SyntaxError struct {
    Offset int64 // location of the error
    What   error // error description
}

func (e *SyntaxError) Error() string {
    return fmt.Sprintf("bencode: syntax error (offset: %d): %s", e.Offset, e.What)
}

// A non-nil error was returned after calling MarshalBencode on a type which
// implements the Marshaler interface.
type MarshalerError struct {
    Type reflect.Type
    Err  error
}

func (e *MarshalerError) Error() string {
    return "bencode: error calling MarshalBencode for type " + e.Type.String() + ": " + e.Err.Error()
}

// A non-nil error was returned after calling UnmarshalBencode on a type which
// implements the Unmarshaler interface.
type UnmarshalerError struct {
    Type reflect.Type
    Err  error
}

func (e *UnmarshalerError) Error() string {
    return "bencode: error calling UnmarshalBencode for type " + e.Type.String() + ": " + e.Err.Error()
}

type UnusedTrailingBytesError struct {
    NumUnusedBytes int
}

func (me UnusedTrailingBytesError) Error() string {
    return fmt.Sprintf("%d unused trailing bytes", me.NumUnusedBytes)
}
