package validator

import (
    "encoding/json"
    "net"
    "regexp"
    "strconv"
    "strings"
    "time"
    "unicode"
)

const (
    // PatternNumeric is numeric
    PatternNumeric = "^[0-9]+$"
    // PatternInt is int
    PatternInt = "^(?:[-+]?(?:0|[1-9][0-9]*))$"
    // PatternFloat is float
    PatternFloat = "^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$"
    // PatternHexadecimal is hexadecimal
    PatternHexadecimal = "^[0-9a-fA-F]+$"
    // PatternAlpha is alpha
    PatternAlpha = "^[a-zA-Z]+$"
    // PatternAlphanumeric is alphanumeric
    PatternAlphanumeric = "^[a-zA-Z0-9]+$"
    // PatternLatitude is latitude
    PatternLatitude = "^[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)$"
    // PatternLongitude is longitude
    PatternLongitude = "^[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)$"
    // PatternBase64 is base64
    PatternBase64 = "^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$"
    // PatternASCII is ASCII
    PatternASCII = "^[\x00-\x7F]+$"
    // PatternPrintableASCII is printable ASCII
    PatternPrintableASCII = "^[\x20-\x7E]+$"
    // PatternIP is ip
    PatternIP = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
    // PatternURLSchema is URL schema
    PatternURLSchema = `((ftp|tcp|udp|wss?|https?):\/\/)`
    // PatternURLUsername is URL username
    PatternURLUsername = `(\S+(:\S*)?@)`
    // PatternURLPath is URL path
    PatternURLPath = `((\/|\?|#)[^\s]*)`
    // PatternURLPort is URL port
    PatternURLPort = `(:(\d{1,5}))`
    // PatternURLIP is URL ip
    PatternURLIP = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
    // PatternURLSubdomain is URL subdomain
    PatternURLSubdomain = `((www\.)|([a-zA-Z0-9]([-\.][-\._a-zA-Z0-9]+)*))`
    // PatternURL is URL
    PatternURL = `^` + PatternURLSchema + `?` + PatternURLUsername + `?` + `((` + PatternURLIP + `|(\[` + PatternIP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + PatternURLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + PatternURLPort + `?` + PatternURLPath + `?$`
    // PatternEmail is email
    PatternEmail = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    // PatternWinPath is win path
    PatternWinPath = `^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$`
    // PatternUnixPath is unix path
    PatternUnixPath = `^(/[^/\x00]*)+/?$`
    // PatternSemver is semver
    PatternSemver = "^v?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(-(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(\\.(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\\+[0-9a-zA-Z-]+(\\.[0-9a-zA-Z-]+)*)?$"
    // PatternFullWidth is full width
    PatternFullWidth = `[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]`
    // PatternHalfWidth is half width
    PatternHalfWidth = `[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]`
    // PatternHexColor is hex color
    PatternHexColor = "^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$"
    // PatternRGBColor is RGB color
    PatternRGBColor = "^rgb\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*\\)$"
    // PatternRGBAColor is RGB color
    PatternRGBAColor = "^rgba\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*((0\\.[0-9]{1})|(1\\.0)|(1))\\)$"
)

// IsNumeric check if the string is numeric.
func IsNumeric(str string) bool {
    return regexp.MustCompile(PatternNumeric).MatchString(str)
}

// IsInt check if the string is int.
func IsInt(str string) bool {
    return regexp.MustCompile(PatternInt).MatchString(str)
}

// IsFloat check if the string is an float.
func IsFloat(str string) bool {
    return regexp.MustCompile(PatternFloat).MatchString(str)
}

// IsHexadecimal check if the string is a hexadecimal number.
func IsHexadecimal(str string) bool {
    return regexp.MustCompile(PatternHexadecimal).MatchString(str)
}

// IsAlpha checks if the string contains only letters (a-zA-Z).
func IsAlpha(str string) bool {
    return regexp.MustCompile(PatternAlpha).MatchString(str)
}

// IsAlphanumeric checks if the string contains only letters(a-zA-Z) and numbers.
func IsAlphanumeric(str string) bool {
    return regexp.MustCompile(PatternAlphanumeric).MatchString(str)
}

// IsIP checks if the string is valid IP.
func IsIP(str string) bool {
    return net.ParseIP(str) != nil
}

// IsIPv4 checks if the string is valid IPv4.
func IsIPv4(str string) bool {
    ip := net.ParseIP(str)
    if ip == nil {
        return false
    }
    return strings.Contains(str, ".")
}

// IsIPv6 checks if the string is valid IPv6.
func IsIPv6(str string) bool {
    ip := net.ParseIP(str)
    if ip == nil {
        return false
    }
    return strings.Contains(str, ":")
}

// IsLatitude checks if the string is valid latitude.
func IsLatitude(str string) bool {
    return regexp.MustCompile(PatternLatitude).MatchString(str)
}

// IsLongitude checks if the string is valid longitude.
func IsLongitude(str string) bool {
    return regexp.MustCompile(PatternLongitude).MatchString(str)
}

// IsBase64 checks if the string is base64 encoded.
func IsBase64(str string) bool {
    return regexp.MustCompile(PatternBase64).MatchString(str)
}

// IsPort checks if a string represents a valid port.
func IsPort(str string) bool {
    if n, err := strconv.Atoi(str); err == nil && n > 0 && n < 65536 {
        return true
    }
    return false
}

// IsURL checks if the string is URL.
func IsURL(str string) bool {
    return regexp.MustCompile(PatternURL).MatchString(str)
}

// IsASCII checks if the string is ASCII.
func IsASCII(str string) bool {
    return regexp.MustCompile(PatternASCII).MatchString(str)
}

// IsPrintableASCII checks if the string is printable ASCII.
func IsPrintableASCII(str string) bool {
    return regexp.MustCompile(PatternPrintableASCII).MatchString(str)
}

// IsEmail checks if the string is email.
func IsEmail(str string) bool {
    return regexp.MustCompile(PatternEmail).MatchString(str)
}

// IsWinPath checks if the string is windows path.
func IsWinPath(str string) bool {
    if regexp.MustCompile(PatternWinPath).MatchString(str) {
        // http://msdn.microsoft.com/en-us/library/aa365247(VS.85).aspx#maxpath
        if len(str[3:]) > 32767 {
            return false
        }
        return true
    }
    return false
}

// IsUnixPath checks if the string is unix path.
func IsUnixPath(str string) bool {
    return regexp.MustCompile(PatternUnixPath).MatchString(str)
}

// IsSemver checks if the string is valid Semantic Version.
func IsSemver(str string) bool {
    return regexp.MustCompile(PatternSemver).MatchString(str)
}

// IsFullWidth checks if the string is contains any full-width chars.
func IsFullWidth(str string) bool {
    return regexp.MustCompile(PatternFullWidth).MatchString(str)
}

// IsHalfWidth checks if the string is contains any half-width chars.
func IsHalfWidth(str string) bool {
    return regexp.MustCompile(PatternHalfWidth).MatchString(str)
}

// IsHash checks if a string is a hash of type algorithm.
// Algorithm is one of
// [ 'md4', 'md5', 'sha1', 'sha256', 'sha384', 'sha512',
// 'ripemd128', 'ripemd160', 'tiger128', 'tiger160', 'tiger192',
// 'crc32', 'crc32b']
func IsHash(str, algorithm string) bool {
    length := "0"
    algo := strings.ToLower(algorithm)

    switch algo {
        case "crc32", "crc32b":
            length = "8"
        case "md5", "md4", "ripemd128", "tiger128":
            length = "32"
        case "sha1", "ripemd160", "tiger160":
            length = "40"
        case "tiger192":
            length = "48"
        case "sha256":
            length = "64"
        case "sha384":
            length = "96"
        case "sha512":
            length = "128"
        default:
            return false
    }

    return regexp.MustCompile("^[a-f0-9]{" + length + "}$").MatchString(str)
}

// IsMAC check if a string is valid MAC address.
// Possible MAC formats:
// 01:23:45:67:89:ab
// 01:23:45:67:89:ab:cd:ef
// 01-23-45-67-89-ab
// 01-23-45-67-89-ab-cd-ef
// 0123.4567.89ab
// 0123.4567.89ab.cdef
func IsMAC(str string) bool {
    _, err := net.ParseMAC(str)
    return err == nil
}

// IsTime check if string is valid according to given format
func IsTime(str string, format string) bool {
    _, err := time.Parse(format, str)
    return err == nil
}

// IsRFC3339Time check if string is valid timestamp value according to RFC3339
func IsRFC3339Time(str string) bool {
    return IsTime(str, time.RFC3339)
}

// IsRFC3339WithoutZoneTime check if string is valid timestamp value according to RFC3339 which excludes the timezone.
func IsRFC3339WithoutZoneTime(str string) bool {
    return IsTime(str, "2006-01-02T15:04:05")
}

// IsJSON check if the string is valid JSON (note: uses json.Unmarshal).
func IsJSON(str string) bool {
    var js json.RawMessage
    return json.Unmarshal([]byte(str), &js) == nil
}

//IsUTFLetter check if the string contains only unicode letter characters.
//Similar to IsAlpha but for all languages. Empty string is valid.
func IsUTFLetter(str string) bool {
    for _, c := range str {
        if !unicode.IsLetter(c) {
            return false
        }
    }
    return true
}

// IsUTFLetterNumeric check if the string contains only unicode letters and numbers. Empty string is valid.
func IsUTFLetterNumeric(str string) bool {
    for _, c := range str {
        if !unicode.IsLetter(c) && !unicode.IsNumber(c) { //letters && numbers are ok
            return false
        }
    }
    return true
}

// IsHexColor check if the string is a hexadecimal color.
func IsHexColor(str string) bool {
    return regexp.MustCompile(PatternHexColor).MatchString(str)
}

// IsRGBColor check if the string is a valid RGB color in form rgb(255, 255, 255).
func IsRGBColor(str string) bool {
    return regexp.MustCompile(PatternRGBColor).MatchString(str)
}

// IsRGBAColor check if the string is a valid RGBA color in form rgb(255, 255, 255, 0.5).
func IsRGBAColor(str string) bool {
    return regexp.MustCompile(PatternRGBAColor).MatchString(str)
}

// IsLowerCase check if the string is lowercase.
func IsLowerCase(str string) bool {
    return str == strings.ToLower(str)
}

// IsUpperCase check if the string is uppercase.
func IsUpperCase(str string) bool {
    return str == strings.ToUpper(str)
}
