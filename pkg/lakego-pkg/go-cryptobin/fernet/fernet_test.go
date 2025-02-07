package fernet

import (
    "time"
    "testing"
    "crypto/aes"
    "encoding/json"
    "encoding/base64"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

type test struct {
    Secret string
    Src    string
    IV     [aes.BlockSize]byte
    Now    time.Time
    TTLSec int `json:"ttl_sec"`
    Token  string
    Desc   string
}

func loadTests(data string) []test {
    var ts []test
    err := json.Unmarshal([]byte(data), &ts)
    if err != nil {
        panic(err)
    }

    return ts
}

func Test_Generate(t *testing.T) {
    for _, tok := range loadTests(testgenerate) {
        k, _ := DecodeKeys(tok.Secret)
        g := make([]byte, encodedLen(len(tok.Src)))
        n := encrypt(g, []byte(tok.Src), tok.IV[:], tok.Now, k[0])
        if n != len(g) {
            t.Errorf("want %v, got %v", len(g), n)
        }

        s := base64.URLEncoding.EncodeToString(g)
        if s != tok.Token {
            t.Errorf("want %q, got %q", tok.Token, g)

            dumpTok(t, tok.Token, len(tok.Token))

            dumpTok(t, s, n)
        }
    }
}

func Test_VerifyOk(t *testing.T) {
    for _, tok := range loadTests(testverify) {
        k, _ := DecodeKeys(tok.Secret)

        dumpTok(t, tok.Token, len(tok.Token))
        ttl := time.Duration(tok.TTLSec) * time.Second
        b := mustBase64DecodeString(tok.Token)
        g := decrypt(nil, b, ttl, tok.Now, k[0])
        if string(g) != tok.Src {
            t.Errorf("got %#v != exp %#v", string(g), tok.Src)
        }
    }
}

func Test_VerifyBad(t *testing.T) {
    for _, tok := range loadTests(testinvalid) {
        if tok.Desc == "invalid base64" {
            continue
        }

        b, err := base64.URLEncoding.DecodeString(tok.Token)
        if err != nil {
            panic(err)
        }

        k, _ := DecodeKeys(tok.Secret)
        ttl := time.Duration(tok.TTLSec) * time.Second
        if g := decrypt(nil, b, ttl, tok.Now, k[0]); g != nil {
            t.Errorf("got %#v", string(g))
        }
    }
}

func Test_VerifyBadBase64(t *testing.T) {
    for _, tok := range loadTests(testinvalid) {
        if tok.Desc != "invalid base64" {
            continue
        }

        k, _ := DecodeKeys(tok.Secret)
        ttl := time.Duration(tok.TTLSec) * time.Second
        if g := Decrypt([]byte(tok.Token), ttl, k); g != nil {
            t.Errorf("got %#v", string(g))
        }
    }
}

func Test_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    k := GenerateKey()
    msg := []byte("tset-data tset-datatset-datatset-datatset-data")

    en, err := Encrypt(msg, k)
    assertNoError(err, "Test_Encrypt-Encrypt")

    if len(en) == 0 {
        t.Error("Encrypt fail")
    }

    ttl := time.Hour
    de := Decrypt(en, ttl, []*Key{k})

    if len(de) == 0 {
        t.Error("Decrypt fail")
    }

    assertEqual(de, msg, "Test_Encrypt-Decrypt")
}

func dumpTok(t *testing.T, s string, n int) {
    tok := mustBase64DecodeString(s)
    dumpField(t, tok, 0, 1)
    dumpField(t, tok, 1, 1+8)
    dumpField(t, tok, 1+8, 1+8+16)
    dumpField(t, tok, 1+8+16, n-32)
    dumpField(t, tok, n-32, n)
}

func dumpField(t *testing.T, b []byte, n, e int) {
    if len(b) < e {
        e = len(b)
    }
    t.Log(b[n:e])
}

func mustBase64DecodeString(s string) []byte {
    b, err := base64.URLEncoding.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return b
}

var testgenerate = `
[
  {
    "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    "now": "1985-10-26T01:20:00-07:00",
    "iv": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    "src": "hello",
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  }
]
`

var testinvalid = `
[
  {
    "desc": "incorrect mac",
    "token": "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "too short",
    "token": "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "invalid base64",
    "token": "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "payload size not multiple of block size",
    "token": "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "payload padding error",
    "token": "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "far-future TS (unacceptable clock skew)",
    "token": "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "expired TTL",
    "token": "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
    "now": "1985-10-26T01:21:31-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "incorrect IV (causes padding error)",
    "token": "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "very short payload size",
    "token": "gAAAAABdnQ1TUKh2OE_ggbyCIxfg",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 0,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "desc": "super short payload size",
    "token": "gAAA",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 0,
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  }
]
`

var testverify = `
[
  {
    "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": 60,
    "src": "hello",
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  },
  {
    "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    "now": "1985-10-26T01:20:01-07:00",
    "ttl_sec": -1,
    "src": "hello",
    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
  }
]
`
