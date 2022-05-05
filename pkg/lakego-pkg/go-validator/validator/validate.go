package validator

import (
    "errors"
    "regexp"
    "strconv"
    "strings"
    "unicode/utf8"
)

// ValidateInt validate 32 bit integer
func ValidateInt(data any, key string, min, max int, def ...int) (int, error) {
    var defVal any
    ldef := len(def)
    if ldef > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return 0, err
    }

    switch val.(type) {
    case int:
        return val.(int), nil
    case string:
        value := val.(string)
        if !IsInt(value) {
            if ldef == 0 {
                return 0, errors.New(key + " must be an integer")
            }
            return def[0], nil
        }

        v, err := strconv.Atoi(value)
        if err != nil {
            if ldef == 0 {
                return 0, errors.New(key + " must be an integer")
            }
            return def[0], nil
        }
        if min != -1 && v < min {
            if ldef == 0 {
                return 0, errors.New(key + " is too small (minimum is " + strconv.Itoa(min) + ")")
            }
            return def[0], nil
        }
        if max != -1 && v > max {
            if ldef == 0 {
                return 0, errors.New(key + " is too big (maximum is " + strconv.Itoa(max) + ")")
            }
            return def[0], nil
        }
        return v, nil
    default:
        return 0, errors.New("type invalid, must be string or int")
    }
}

// ValidateIntp Validate 32 bit integer with custom error info.
// if err != nil will panic.
func ValidateIntp(data any, key string, min, max int, code int, message string, def ...int) int {
    val, err := ValidateInt(data, key, min, max, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateInt64 Validate 64 bit integer.
func ValidateInt64(data any, key string, min, max int64, def ...int64) (int64, error) {
    var defVal any
    ldef := len(def)
    if ldef > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return 0, err
    }

    switch val.(type) {
    case int64:
        return val.(int64), nil
    case string:
        value := val.(string)
        if !IsInt(value) {
            if ldef == 0 {
                return 0, errors.New(key + " must be a valid interger")
            }
            return def[0], nil
        }

        v, err := strconv.ParseInt(value, 10, 64)
        if err != nil {
            if ldef == 0 {
                return 0, errors.New(key + " must be a valid interger")
            }
            return def[0], nil
        }
        if min != -1 && v < min {
            if ldef == 0 {
                return 0, errors.New(key + " is too small (minimum is " + strconv.FormatInt(min, 10) + ")")
            }
            return def[0], nil
        }
        if max != -1 && v > max {
            if ldef == 0 {
                return 0, errors.New(key + " is too big (maximum is " + strconv.FormatInt(max, 10) + ")")
            }
            return def[0], nil
        }
        return v, nil
    default:
        return 0, errors.New("type invalid, must be string or int64")
    }
}

// ValidateInt64p Validate 64 bit integer with custom error info.
// if err != nil will panic.
func ValidateInt64p(data any, key string, min, max int64, code int, message string, def ...int64) int64 {
    val, err := ValidateInt64(data, key, min, max, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateFloat validate 64 bit float.
func ValidateFloat(data any, key string, min, max float64, def ...float64) (float64, error) {
    var defVal any
    ldef := len(def)
    if ldef > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return 0, err
    }

    switch val.(type) {
    case float64:
        return val.(float64), nil
    case string:
        value := val.(string)
        if !IsFloat(value) {
            if ldef == 0 {
                return 0, errors.New(key + " must be a valid float64")
            }
            return def[0], nil
        }

        v, err := strconv.ParseFloat(value, 64)
        if err != nil {
            if ldef == 0 {
                return 0, errors.New(key + " must be a valid float64")
            }
            return def[0], nil
        }
        if min != -1 && v < min {
            if ldef == 0 {
                return 0, errors.New(key + " is too small (minimum is " + strconv.FormatFloat(min, 'f', -1, 64) + ")")
            }
            return def[0], nil
        }
        if max != -1 && v > max {
            if ldef == 0 {
                return 0, errors.New(key + " is too big (maximum is " + strconv.FormatFloat(max, 'f', -1, 64) + ")")
            }
            return def[0], nil
        }
        return v, nil
    default:
        return 0, errors.New("type invalid, must be string or float64")
    }
}

// ValidateFloatp validate 64 bit float with custom error info.
// if err != nil will panic.
func ValidateFloatp(data any, key string, min, max float64, code int, message string, def ...float64) float64 {
    val, err := ValidateFloat(data, key, min, max, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateString validate string.
func ValidateString(data any, key string, min, max int, def ...string) (string, error) {
    var defVal any
    if len(def) > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return "", err
    }

    length := utf8.RuneCountInString(val.(string))
    if len(def) > 0 && length == 0 {
        return def[0], nil
    }
    if min != -1 && length < min {
        return "", errors.New(key + " is too short (minimum is " + strconv.Itoa(min) + " characters)")
    }
    if max != -1 && length > max {
        return "", errors.New(key + " is too long (maximum is " + strconv.Itoa(max) + " characters)")
    }
    return val.(string), nil
}

// ValidateStringp validate string with custom error info.
// if err != nil will panic.
func ValidateStringp(data any, key string, min, max int, code int, message string, def ...string) string {
    val, err := ValidateString(data, key, min, max, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateStringWithPattern validate string with regexp pattern.
func ValidateStringWithPattern(data any, key, pattern string, def ...string) (string, error) {
    var defVal any
    ldef := len(def)
    if ldef > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return "", err
    }
    if !regexp.MustCompile(pattern).MatchString(val.(string)) {
        if ldef == 0 {
            return "", errors.New(key + " must be a valid string")
        }
        return def[0], nil
    }

    return val.(string), nil
}

// ValidateStringWithPatternp validateStringWithPatternp validate string with regex pattern.
// if err != nil will panic.
func ValidateStringWithPatternp(data any, key, pattern string, code int, message string, def ...string) string {
    val, err := ValidateStringWithPattern(data, key, pattern, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateEnumInt validate enum int.
func ValidateEnumInt(data any, key string, validValues []int, def ...int) (int, error) {
    val, err := ValidateInt(data, key, -1, -1, def...)
    if err != nil {
        return 0, nil
    }
    for _, v := range validValues {
        if v == val {
            return val, nil
        }
    }
    return 0, errors.New(key + " is invalid")
}

// ValidateEnumIntp validate enum int with custom error info.
// if err != nil will panic.
func ValidateEnumIntp(data any, key string, validValues []int, code int, message string, def ...int) int {
    val, err := ValidateEnumInt(data, key, validValues, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateEnumInt64 validate enum int64
func ValidateEnumInt64(data any, key string, validValues []int64, def ...int64) (int64, error) {
    val, err := ValidateInt64(data, key, -1, -1, def...)
    if err != nil {
        return 0, err
    }
    for _, v := range validValues {
        if v == val {
            return val, nil
        }
    }
    return 0, errors.New(key + " is invalid")
}

// ValidateEnumInt64p Validate enum int64 with panic.
// if err != nil will panic.
func ValidateEnumInt64p(data any, key string, validValues []int64, code int, message string, def ...int64) int64 {
    val, err := ValidateEnumInt64(data, key, validValues, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateEnumString validate enum string
func ValidateEnumString(data any, key string, validValues []string, def ...string) (string, error) {
    val, err := ValidateString(data, key, -1, -1, def...)
    if err != nil {
        return "", nil
    }
    for _, v := range validValues {
        if v == val {
            return val, nil
        }
    }
    return "", errors.New(key + " is invalid")
}

// ValidateEnumStringp validate enum string with custom error info.
// if err != nil will panic.
func ValidateEnumStringp(data any, key string, validValues []string, code int, message string, def ...string) string {
    val, err := ValidateEnumString(data, key, validValues, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// ValidateSlice validate slice.
func ValidateSlice(data any, key, sep string, min, max int, def ...string) ([]string, error) {
    var defVal any
    if len(def) > 0 {
        defVal = def[0]
    }
    val, err := checkExist(data, key, defVal)
    if err != nil {
        return nil, err
    }

    vals := strings.Split(val.(string), sep)
    length := len(vals)
    if min != -1 && length < min {
        return nil, errors.New(key + " is too short (minimum is " + strconv.Itoa(min) + " elements)")
    }
    if max != -1 && length > max {
        return nil, errors.New(key + " is too long (maximum is " + strconv.Itoa(max) + " elements)")
    }
    return vals, nil
}

// ValidateSlicep validate slice with custom error info.
// if err != nil will panic.
func ValidateSlicep(data any, key, sep string, min, max int, code int, message string, def ...string) []string {
    val, err := ValidateSlice(data, key, sep, min, max, def...)
    if err != nil {
        panic(NewError(err.Error(), code, message))
    }
    return val
}

// Chekc exist
func checkExist(data any, key string, def any) (any, error) {
    var val string
    switch data.(type) {
    case string:
        val = data.(string)
    case map[string]string:
        if value, ok := data.(map[string]string)[key]; ok {
            val = value
        } else {
            if def == nil {
                return nil, errors.New(key + " is required")
            }
            return def, nil
        }
    default:
        return nil, errors.New("data type invalid, must be string or map[string]string")
    }

    if val == "" {
        if def == nil {
            return nil, errors.New(key + " can't be empty")
        }
        return def, nil
    }

    return val, nil
}
