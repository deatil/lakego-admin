package encoding

// 字节
func FromBytes(data []byte) Encoding {
    return New().FromBytes(data)
}

// 字符
func FromString(data string) Encoding {
    return New().FromString(data)
}

// Base32
func FromBase32String(data string) Encoding {
    return New().FromBase32String(data)
}

// Base58
func FromBase58String(data string) Encoding {
    return New().FromBase58String(data)
}

// Base64
func FromBase64String(data string) Encoding {
    return New().FromBase64String(data)
}

// Base85
func FromBase85String(data string) Encoding {
    return New().FromBase85String(data)
}

// Hex
func FromHexString(data string) Encoding {
    return New().FromHexString(data)
}

// Gob
func ForGob(data interface{}) Encoding {
    return New().ForGob(data)
}

// Xml
func ForXML(data interface{}) Encoding {
    return New().ForXML(data)
}

// JSON
func ForJSON(data interface{}) Encoding {
    return New().ForJSON(data)
}

// Binary
func ForBinary(data interface{}) Encoding {
    return New().ForBinary(data)
}

// Csv
func ForCsv(data [][]string) Encoding {
    return New().ForCsv(data)
}

// Asn1
func ForAsn1(data interface{}, params ...string) Encoding {
    return New().ForAsn1(data, params...)
}
