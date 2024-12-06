package pkcs12

import (
    "github.com/deatil/go-cryptobin/tool/bmp_string"
)

var (
    // BmpStringZeroTerminated returns s encoded in UCS-2 with a zero terminator.
    bmpStringZeroTerminated = bmp_string.BmpStringZeroTerminated

    // BmpString returns s encoded in UCS-2
    bmpString = bmp_string.BmpString

    // DecodeBMPString return utf-8 string
    decodeBMPString = bmp_string.DecodeBMPString
)
