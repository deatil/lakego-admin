package hash

// MD5_16
func MD5_16(s string) string {
    data := FromString(s).MD5().ToHexString()

    return data[8:24]
}
