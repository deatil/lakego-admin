package pmac

import (
    "bytes"
    "testing"
    "encoding/hex"
    "encoding/json"
)

type dblExample struct {
    input  []byte
    output []byte
}

var testData = `
{
  "list":[
    {
      "input:d16":"00000000000000000000000000000000",
      "output:d16":"00000000000000000000000000000000"
    },
    {
      "input:d16":"00000000000000000000000000000001",
      "output:d16":"00000000000000000000000000000002"
    },
    {
      "input:d16":"ffffffffffffffffffffffffffffffff",
      "output:d16":"ffffffffffffffffffffffffffffff79"
    },
    {
      "input:d16":"52a2d82a687330bd45d4edb9f3b06527",
      "output:d16":"a545b054d0e6617a8ba9db73e760ca4e"
    },
    {
      "input:d16":"6e56610687fe93be1ef69690067b4b7b",
      "output:d16":"dcacc20d0ffd277c3ded2d200cf696f6"
    },
    {
      "input:d16":"d2535bfca5898b81124613fdf94e3d7b",
      "output:d16":"a4a6b7f94b131702248c27fbf29c7a71"
    },
    {
      "input:d16":"e84b7dda057e100628860a3cdac155c0",
      "output:d16":"d096fbb40afc200c510c1479b582ab07"
    }
  ]
}
`

// Load test vectors
func loadDblExamples() []dblExample {
    var examplesJSON map[string]interface{}

    exampleData := []byte(testData)

    if err := json.Unmarshal(exampleData, &examplesJSON); err != nil {
        panic(err)
    }

    examplesArray := examplesJSON["list"].([]interface{})

    if examplesArray == nil {
        panic("no toplevel 'list' key in dbl.tjson")
    }

    result := make([]dblExample, len(examplesArray))

    for i, exampleJSON := range examplesArray {
        example := exampleJSON.(map[string]interface{})

        inputHex := example["input:d16"].(string)
        input := make([]byte, hex.DecodedLen(len(inputHex)))

        if _, err := hex.Decode(input, []byte(inputHex)); err != nil {
            panic(err)
        }

        outputHex := example["output:d16"].(string)
        output := make([]byte, hex.DecodedLen(len(outputHex)))

        if _, err := hex.Decode(output, []byte(outputHex)); err != nil {
            panic(err)
        }

        result[i] = dblExample{input, output}
    }

    return result
}

func TestDbl(t *testing.T) {
    for i, tt := range loadDblExamples() {
        size := len(tt.input)

        var b Block = Block{
            Data: make([]byte, size),
            Size: size,
        }

        copy(b.Data, tt.input)
        b.Dbl()

        if !bytes.Equal(b.Data, tt.output) {
            t.Errorf("test %d: dbl mismatch\n\twant %x\n\thave %x", i, tt.output, b)
            continue
        }
    }
}
