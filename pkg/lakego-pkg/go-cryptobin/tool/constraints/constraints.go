package constraints

// Signed is a constraint that permits any signed integer type.
type Signed interface{
    ~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Unsigned is a constraint that permits any unsigned integer type.
type Unsigned interface{
    ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// Integer is a constraint that permits any integer type.
type Integer interface{
    Signed | Unsigned
}

// Float is a constraint that permits any floating-point type.
type Float interface{
    ~float32 | ~float64
}

// Complex is a constraint that permits any complex numeric type.
type Complex interface{
    ~complex64 | ~complex128
}

// IntegerFloat is a constraint that permits any integer and floating-point type.
type IntegerFloat interface{
    Integer | Float
}

// Ordered is a constraint that permits any ordered type: any type
// that supports the operators < <= >= >.
type Ordered interface{
    Integer | Float | ~string
}

// MathInteger is a constraint that permits any integer, floating-point and complex numeric type.
type MathInteger interface{
    Integer | Float | Complex
}
