package encoding

import (
    "testing"
    "encoding/base64"
)

type testEncoding struct {}

// Encode
func (this testEncoding) Encode(data []byte, cfg ...map[string]any) ([]byte, error) {
    newData := base64.StdEncoding.EncodeToString(data)

    return []byte(newData), nil
}

// Decode
func (this testEncoding) Decode(data []byte, cfg ...map[string]any) ([]byte, error) {
    return base64.StdEncoding.DecodeString(string(data))
}

func init() {
    UseEncoding.Add("TestEncoding", func() IEncoding {
        return testEncoding{}
    })
}

func Test_UseEncoding(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass123"

    en := FromString(data).EncodeBy("TestEncoding")
    enStr := en.ToString()

    assertError(en.Error, "UseEncoding Encode error")

    de := FromString(enStr).DecodeBy("TestEncoding")
    deStr := de.ToString()

    assertError(de.Error, "UseEncoding Decode error")

    assert(data, deStr, "UseEncoding")
}
