package pkcs12

import (
    "github.com/deatil/go-cryptobin/tool"
)

var (
    // BmpStringZeroTerminated returns s encoded in UCS-2 with a zero terminator.
    bmpStringZeroTerminated = tool.BmpStringZeroTerminated

    // BmpString returns s encoded in UCS-2
    bmpString = tool.BmpString

    // DecodeBMPString return utf-8 string
    decodeBMPString = tool.DecodeBMPString
)
