package k12

import(
    "fmt"
    "hash"
    "testing"
    "encoding/hex"
)

func pattern(length int) (result []byte) {
    char := 0

    for i := 0; i < length; i++ {
        result = append(result, byte(char))
        char ++
        if char % 0xFB == 0 {
            char = 0
        }
    }

    return
}

func Test_Interface(t *testing.T) {
    var _ hash.Hash = &digest{}
}

func Test_Check(t *testing.T) {
    for i, vector := range vectors {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            {
                out := SumWithSize(vector.customString, vector.message, vector.outputLen)
                if len(out) == 10032 {
                    out = out[10000:]
                }

                if temp := hex.EncodeToString(out); temp != vector.expectedOutput {
                    t.Errorf("SumWithSize fail, got %s, want %s", vector.expectedOutput, temp)
                }
            }

            {
                h := NewWithSize(vector.customString, vector.outputLen)
                h.Write(vector.message)
                out := h.Sum(nil)

                if len(out) == 10032 {
                    out = out[10000:]
                }

                if temp := hex.EncodeToString(out); temp != vector.expectedOutput {
                    t.Errorf("NewWithSize fail, got %s, want %s", vector.expectedOutput, temp)
                }
            }

            {
                h := NewWithSize(vector.customString, vector.outputLen)
                h.Write(vector.message[:len(vector.message)/2])
                h.Sum(nil)
                h.Write(vector.message[len(vector.message)/2:])
                out := h.Sum(nil)

                if len(out) == 10032 {
                    out = out[10000:]
                }

                if temp := hex.EncodeToString(out); temp != vector.expectedOutput {
                    t.Errorf("NewWithSize 2 fail, got %s, want %s", vector.expectedOutput, temp)
                }
            }

        })
    }
}

type testVectors struct{
    message []byte
    customString []byte
    outputLen int
    expectedOutput string
}

var vectors = []testVectors{
    {[]byte{}, []byte{}, 32, "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"},
    {[]byte{}, []byte{}, 64, "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71"},
    {[]byte{}, []byte{}, 10032, "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d"},
    {pattern(1), []byte{}, 32, "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f"},
    {pattern(17), []byte{}, 32, "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888"},
    {pattern(289), []byte{}, 32, "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c"},
    {pattern(4913), []byte{}, 32, "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0"},
    {pattern(83521), []byte{}, 32, "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe"},
    {pattern(1419857), []byte{}, 32, "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682"},
    {pattern(24137569), []byte{}, 32, "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8"},
    {[]byte{}, pattern(1), 32, "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583"},
    {[]byte{0xff}, pattern(41), 32, "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"},
    {[]byte{0xff, 0xff, 0xff}, pattern(1681), 32, "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74"},
    {[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, pattern(68921), 32, "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf"},
}
