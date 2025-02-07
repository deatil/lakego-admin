## go-encoding

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-encoding" ><img src="https://pkg.go.dev/badge/deatil/go-encoding.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-encoding" ><img src="https://codecov.io/gh/deatil/go-encoding/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-encoding" />
</p>

[中文](README_CN.md) | English


### Desc

*  data encoding/decoding pkg
*  encodings has some (Hex/Base32/Base36/Base45/Base58/Base62/Base64/Base85/Base91/Base92/Base100/MorseITU/JSON)


### Download

~~~go
go get -u github.com/deatil/go-encoding
~~~


### Get Starting

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-encoding/encoding"
)

func main() {
    oldData := "useData"

    // Base64 Encode
    base64Data := encoding.
        FromString(oldData).
        Base64Encode().
        ToString()
    fmt.Println("Base64 Encoded：", base64Data)

    // Base64 Decode
    base64DecodeData := encoding.
        FromString(base64Data).
        Base64Decode().
        ToString()
    fmt.Println("Base64 Decoded：", base64DecodeData)
}
~~~


### Use encoding

~~~go
base64Data := encoding.
    FromString(oldData). // input data
    Base64Encode().      // encoding/decoding type
    ToString()           // output data
~~~


### Input and Output

*  Input:
`FromBytes(data []byte)`, `FromString(data string)`, `FromReader(reader io.Reader)`
*  Output:
`String() string`, `ToBytes() []byte`, `ToString() string`, `ToReader() io.Reader`


### Encoding Types

*  Decode:
`Base32Encode()`, `Base32RawEncode()`,  `Base32HexEncode()`,`Base32RawHexEncode()`,  `Base32EncodeWithEncoder(encoder string)`, `Base32RawEncodeWithEncoder(encoder string)`,
`Base45Encode()`,
`Base58Encode()`,
`Base62Encode()`,
`Base64Encode()`, `Base64URLEncode()`, `Base64RawEncode()`, `Base64RawURLEncode()`, `Base64SegmentEncode()`, `Base64EncodeWithEncoder(encoder string)`,
`Base85Encode()`,
`Base91Encode()`,
`Base100Encode()`,
`Basex2Encode()`, `Basex16Encode()`, `Basex62Encode()`, `BasexEncodeWithEncoder(encoder string)`,
`HexEncode()`,
`MorseITUEncode()`,
`SafeURLEncode()`,
`SerializeEncode()`,
`JSONEncode(data any)`, `JSONIteratorEncode(data any)`, `JSONIteratorIndentEncode(v any, prefix, indent string)`,
`GobEncode(data any)`

*  Encode:
`Base32Decode()`, `Base32RawDecode()`,  `Base32HexDecode()`,`Base32RawHexDecode()`,  `Base32DecodeWithEncoder(encoder string)`, `Base32RawDecodeWithEncoder(encoder string)`,
`Base45Decode()`,
`Base58Decode()`,
`Base62Decode()`,
`Base64Decode()`, `Base64URLDecode()`, `Base64RawDecode()`, `Base64RawURLDecode()`, `Base64SegmentDecode(paddingAllowed ...bool)`, `Base64DecodeWithEncoder(encoder string)`,
`Base85Encode()`,
`Base91Decode()`,
`Base100Decode()`,
`Basex2Decode()`, `Basex16Decode()`, `Basex62Decode()`, `BasexDecodeWithEncoder(encoder string)`,
`HexDecode()`,
`MorseITUDecode()`,
`SafeURLDecode()`,
`SerializeDecode()`,
`JSONDecode(dst any)`, `JSONIteratorDecode(dst any)`,
`GobDecode(dst any)`


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
