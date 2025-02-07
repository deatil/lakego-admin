package base58

import (
    "bytes"
    "testing"
)

func Test_Encode(t *testing.T) {
    for _, s := range SamplesStd {
        encoded := StdEncoding.Encode([]byte(s.source))
        if bytes.Equal(encoded, s.targetBytes) {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            str := string(encoded)
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), str, len(str))
        }
    }
}

func Test_EncodeToString(t *testing.T) {
    for _, s := range SamplesStd {
        encoded := StdEncoding.EncodeToString([]byte(s.source))
        if len(encoded) == len(s.target) && encoded == s.target {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), encoded, len(encoded))
        }
    }
}

func Test_Decode(t *testing.T) {
    for _, s := range SamplesStd {
        decoded, err := StdEncoding.Decode(s.targetBytes)
        if err != nil {
            t.Error(err)
            continue
        }
        if bytes.Equal(decoded, s.sourceBytes) {
            t.Logf("target: %-15s\tsource: %s", s.target, s.source)
        } else {
            str := string(decoded)
            t.Errorf("target: %-15s\texpected source: %s(%d)\tactual source: %s(%d)", s.target, s.source, len(s.source), str, len(str))
        }
    }
}

func Test_DecodeString(t *testing.T) {
    for _, s := range SamplesStd {
        decoded, err := StdEncoding.DecodeString(s.target)
        if err != nil {
            t.Error(err)
            continue
        }
        if bytes.Equal(decoded, s.sourceBytes) {
            t.Logf("target: %-15s\tsource: %s", s.target, s.source)
        } else {
            str := string(decoded)
            t.Errorf("target: %-15s\texpected source: %s(%d)\tactual source: %s(%d)", s.target, s.source, len(s.source), str, len(str))
        }
    }
}

func Test_EncodeWithCustomAlphabet(t *testing.T) {
    for _, s := range SamplesWithAlphabet {
        encoded := NewEncoding(s.alphabet).Encode([]byte(s.source))
        if bytes.Equal(encoded, s.targetBytes) {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            str := string(encoded)
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), str, len(str))
        }
    }
}

func Test_DecodeWithCustomAlphabet(t *testing.T) {
    for _, s := range SamplesWithAlphabet {
        decoded, err := NewEncoding(s.alphabet).Decode(s.targetBytes)
        if err != nil {
            t.Error(err)
            continue
        }
        if bytes.Equal(decoded, s.sourceBytes) {
            t.Logf("target: %-15s\tsource: %s", s.target, s.source)
        } else {
            str := string(decoded)
            t.Errorf("target: %-15s\texpected source: %s(%d)\tactual source: %s(%d)", s.target, s.source, len(s.source), str, len(str))
        }
    }
}

func Test_DecodeError(t *testing.T) {
    for _, s := range SamplesErr {
        decoded, err := StdEncoding.Decode(s.targetBytes)
        if err != nil {
            t.Logf("%s: \"%c\"", err.Error(), err)
            continue
        }

        str := string(decoded)
        t.Errorf("An error should have occurred, instead of returning \"%s\"", str)
    }
}

func Test_CheckEncode(t *testing.T) {
    input := []byte("test-date")
    version := byte(12)

    res := CheckEncode(input, version)

    decoded, ver, _ := CheckDecode(res)

    if !bytes.Equal(decoded, input) {
        t.Errorf("input got: %s(%d), want: %s(%d)", string(decoded), len(decoded), string(input), len(input))
    }

    if ver != version {
        t.Errorf("version got: %d, want: %d", ver, version)
    }
}

func NewSample(source, target string) *Sample {
    return &Sample{source: source, target: target, sourceBytes: []byte(source), targetBytes: []byte(target)}
}

func NewSampleWithAlphabet(source, target, alphabet string) *Sample {
    return &Sample{source: source, target: target, sourceBytes: []byte(source), targetBytes: []byte(target), alphabet: alphabet}
}

type Sample struct {
    source      string
    target      string
    sourceBytes []byte
    targetBytes []byte
    alphabet    string
}

var SamplesStd = []*Sample{
    NewSample("", ""),
    NewSample("f", "2m"),
    NewSample("fo", "8o8"),
    NewSample("foo", "bQbp"),
    NewSample("foob", "3csAg9"),
    NewSample("fooba", "CZJRhmz"),
    NewSample("foobar", "t1Zv2yaZ"),

    NewSample("su", "9nc"),
    NewSample("sur", "fnKT"),
    NewSample("sure", "3xB2TW"),
    NewSample("sure.", "E2XFRyo"),
    NewSample("asure.", "qXcNm9C1"),
    NewSample("easure.", "4qq4WqChgZ"),
    NewSample("leasure.", "K8aUZhGUNaR"),

    NewSample("=", "24"),
    NewSample(">", "25"),
    NewSample("?", "26"),
    NewSample("11", "4k8"),
    NewSample("111", "HXLk"),
    NewSample("1111", "2Fvv9e"),
    NewSample("11111", "6Ytyb9A"),
    NewSample("111111", "RVnQmh1a"),

    NewSample("Hello, World!", "72k1xXWG59fYdzSNoA"),
    NewSample("你好，世界！", "AVGu5T9j8gbKjDaBawMj5iGit"),
    NewSample("こんにちは", "7NAasPYBzpyEe5hmwr1KL"),
    NewSample("안녕하십니까", "Ap9GxMvMvB9xzEbvcweFMBLEX"),
}

var SamplesWithAlphabet = []*Sample{
    NewSampleWithAlphabet("", "", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("f", "Bv", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("fo", "HxH", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("foo", "kZky", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("foob", "Cl2KqJ", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("fooba", "MiTarv9", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("foobar", "3Ai5B8ji", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),

    NewSampleWithAlphabet("su", "Jwl", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("sur", "pwUc", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("sure", "C7LBcf", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("sure.", "PBgQa8x", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("asure.", "zglXvJMA", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("easure.", "DzzDfzMrqi", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("leasure.", "UHjdirRdXja", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),

    NewSampleWithAlphabet("=", "BD", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet(">", "BE", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("?", "BF", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("11", "DuH", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("111", "SgVu", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("1111", "BQ55Jn", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("11111", "Fh38kJK", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("111111", "aewZvrAj", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),

    NewSampleWithAlphabet("Hello, World!", "GBuA7gfREJphm9bXxK", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("你好，世界！", "KeR4EcJtHqkUtNjLj6WtEsRs3", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("こんにちは", "GXKj2YhL9y8PnErv61AUV", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
    NewSampleWithAlphabet("안녕하십니까", "KyJR7W5W5LJ79Pk5l6nQWLVPg", "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz123456789"),
}

var SamplesErr = []*Sample{
    NewSample("", "Hello, World!"),
    NewSample("", "哈哈"),
    NewSample("", "はは"),
}
