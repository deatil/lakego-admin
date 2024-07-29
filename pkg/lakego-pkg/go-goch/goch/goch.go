package goch

import "time"

// ToBool casts an interface to a bool type.
func ToBool(i any) bool {
    v, _ := ToBoolE(i)
    return v
}

// ToTime casts an interface to a time.Time type.
func ToTime(i any) time.Time {
    v, _ := ToTimeE(i)
    return v
}

func ToTimeInDefaultLocation(i any, location *time.Location) time.Time {
    v, _ := ToTimeInDefaultLocationE(i, location)
    return v
}

// ToDuration casts an interface to a time.Duration type.
func ToDuration(i any) time.Duration {
    v, _ := ToDurationE(i)
    return v
}

// ToFloat64 casts an interface to a float64 type.
func ToFloat64(i any) float64 {
    v, _ := ToFloat64E(i)
    return v
}

// ToFloat32 casts an interface to a float32 type.
func ToFloat32(i any) float32 {
    v, _ := ToFloat32E(i)
    return v
}

// ToInt64 casts an interface to an int64 type.
func ToInt64(i any) int64 {
    v, _ := ToInt64E(i)
    return v
}

// ToInt32 casts an interface to an int32 type.
func ToInt32(i any) int32 {
    v, _ := ToInt32E(i)
    return v
}

// ToInt16 casts an interface to an int16 type.
func ToInt16(i any) int16 {
    v, _ := ToInt16E(i)
    return v
}

// ToInt8 casts an interface to an int8 type.
func ToInt8(i any) int8 {
    v, _ := ToInt8E(i)
    return v
}

// ToInt casts an interface to an int type.
func ToInt(i any) int {
    v, _ := ToIntE(i)
    return v
}

// ToUint casts an interface to a uint type.
func ToUint(i any) uint {
    v, _ := ToUintE(i)
    return v
}

// ToUint64 casts an interface to a uint64 type.
func ToUint64(i any) uint64 {
    v, _ := ToUint64E(i)
    return v
}

// ToUint32 casts an interface to a uint32 type.
func ToUint32(i any) uint32 {
    v, _ := ToUint32E(i)
    return v
}

// ToUint16 casts an interface to a uint16 type.
func ToUint16(i any) uint16 {
    v, _ := ToUint16E(i)
    return v
}

// ToUint8 casts an interface to a uint8 type.
func ToUint8(i any) uint8 {
    v, _ := ToUint8E(i)
    return v
}

// ToString casts an interface to a string type.
func ToString(i any) string {
    v, _ := ToStringE(i)
    return v
}

// ToStringMapString casts an interface to a map[string]string type.
func ToStringMapString(i any) map[string]string {
    v, _ := ToStringMapStringE(i)
    return v
}

// ToStringMapStringSlice casts an interface to a map[string][]string type.
func ToStringMapStringSlice(i any) map[string][]string {
    v, _ := ToStringMapStringSliceE(i)
    return v
}

// ToStringMapBool casts an interface to a map[string]bool type.
func ToStringMapBool(i any) map[string]bool {
    v, _ := ToStringMapBoolE(i)
    return v
}

// ToStringMapInt casts an interface to a map[string]int type.
func ToStringMapInt(i any) map[string]int {
    v, _ := ToStringMapIntE(i)
    return v
}

// ToStringMapInt64 casts an interface to a map[string]int64 type.
func ToStringMapInt64(i any) map[string]int64 {
    v, _ := ToStringMapInt64E(i)
    return v
}

// ToStringMap casts an interface to a map[string]any type.
func ToStringMap(i any) map[string]any {
    v, _ := ToStringMapE(i)
    return v
}

// ToSlice casts an interface to a []any type.
func ToSlice(i any) []any {
    v, _ := ToSliceE(i)
    return v
}

// ToBoolSlice casts an interface to a []bool type.
func ToBoolSlice(i any) []bool {
    v, _ := ToBoolSliceE(i)
    return v
}

// ToStringSlice casts an interface to a []string type.
func ToStringSlice(i any) []string {
    v, _ := ToStringSliceE(i)
    return v
}

// ToIntSlice casts an interface to a []int type.
func ToIntSlice(i any) []int {
    v, _ := ToIntSliceE(i)
    return v
}

// ToDurationSlice casts an interface to a []time.Duration type.
func ToDurationSlice(i any) []time.Duration {
    v, _ := ToDurationSliceE(i)
    return v
}

// ToJSON casts an interface to []type.
func ToJSON(i any) string {
    v, _ := ToJSONE(i)
    return v
}
