package validator

import (
    "regexp"
)

const (
    // PatternHasLowerCase check has lower case
    PatternHasLowerCase = ".*[[:lower:]]"
    // PatternHasUpperCase check has upper case
    PatternHasUpperCase = ".*[[:upper:]]"
)

// HasLowerCase check if the string contains at least 1 lowercase.
func HasLowerCase(str string) bool {
    return regexp.MustCompile(PatternHasLowerCase).MatchString(str)
}

// HasUpperCase check if the string contains as least 1 uppercase.
func HasUpperCase(str string) bool {
    return regexp.MustCompile(PatternHasUpperCase).MatchString(str)
}
