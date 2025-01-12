package argon2

import (
    "strings"
    "testing"
    "crypto/rand"
)

func Test_GenerateSaltedHash(t *testing.T) {
    tests := []struct {
        name         string
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", "Password1", 7, 109, false},
        {"Should Not Work", "", 1, 0, true},
        {"Should Work 2", "gS</5Tu>3@(<FCtY", 7, 109, false},
        {"Should Work 3", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 109, false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHash(rand.Reader, tt.password)
            hashSegments := strings.Split(got, "$")
            if (err != nil) != tt.wantErr {
                t.Errorf("GenerateSaltedHash() = %v, want %v", err, tt.wantErr)
                return
            }

            if len(hashSegments) != tt.hashSegments {
                t.Errorf("GenerateSaltedHash() had %d segments. Want %d", len(hashSegments), tt.hashSegments)
            }
            if len(got) != tt.hashLength {
                t.Errorf("GenerateSaltedHash() hash length = %v, want %v", len(got), tt.hashLength)
            }
        })
    }
}

func Test_CompareHashWithPassword(t *testing.T) {
    tests := []struct {
        name     string
        hash     string
        password string
        isValid  bool
        wantErr  bool
    }{
        {"Should Work 1", `argon2id$19$65536$3$2$R8kBdA675bqNJbhWntdlAA$X28Igb1N0MBO3IWOIPoS+JxLmhAx0KBUYe65BSEsMs8`, `qwerty123`, true, false},
        {"Should Not Work 1", `argon2id$19$65536$3$2$6pAg+fVI6vB9uynAuOTK0B$VPg50e+vxRnvQ9dIFSg1HFNYHYcxEW+Dx47O6vipImU`, `qwerty123`, false, true},
        {"Should Not Work 2", ``, ``, false, true},
        {"Should Not Work 3", `badHash`, ``, false, true},
        {"Should Work 2", `argon2id$19$65536$3$2$y9Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck`, `qwerty123`, true, false},
        {"Should Not Work 4", `argon2id$19$65536$3$2$y7Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck`, `qwerty123`, false, true},
        {"Should Not Work 5", `argon2id$65536$3$2$y9Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck`, `qwerty123`, false, true},
        {"Should Work 3", `argon2d$19$65536$1$4$kBukCPS4IEJ4xDde6M3XetbSutA4wBK1WUVEf0c+Iuo$ULQg74UC/lmnV6I6bEVW8Gtk6bqa89PE78bf+ot3LA4`, `qwerty123`, true, false},
        {"Should Work 31", `argon2id$19$65536$3$2$6pAg+fVI2vB9uenAuOTK0A$VPg50e+vxRnvQ8dIFSg1HFNYHYcxEW+Dx47O6vipImU`, `qwerty123`, true, false},
        {"Should Work 5", `argon2i$19$65536$1$4$HVZ4vlSeA9OejpkNfxDTTA+wi1DSpi23HP8QLrfmFsU$7L8JxqudLuNKzvmJmyTmgSl0mvF39aG6vOMFB+7NBX4`, `Password1`, true, false},
        {"Should Not Work 6", `argon2i$17$65536$1$4$HVZ4vlSeA9OejpkNfxDTTA+wi1DSpi23HP8QLrfmFsU$7L8JxqudLuNKzvmJmyTmgSl0mvF39aG6vOMFB+7NBX4`, `Password1`, false, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := CompareHashWithPassword(tt.hash, tt.password)
            if (err != nil) != tt.wantErr {
                t.Errorf("CompareHashWithPassword() error = %v, wantErr %v", err, tt.wantErr)
                t.Errorf("hash is %v", got)
                return
            }

            if got != tt.isValid {
                t.Errorf("CompareHashWithPassword() = %v, want %v", got, tt.isValid)
            }
        })
    }
}

func Test_GenerateSaltedHashWithType(t *testing.T) {
    tests := []struct {
        name         string
        typ          Argon2Type
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", Argon2id, "Password1", 7, 109, false},
        {"Should Not Work", Argon2id, "", 1, 0, true},
        {"Should Work 2", Argon2id, "gS</5Tu>3@(<FCtY", 7, 109, false},
        {"Should Work 3", Argon2id, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 109, false},
        {"Should Work 31", Argon2i, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 108, false},
        {"Should Not Work 2", Argon2i, "", 1, 0, true},
        {"Should Work 5", Argon2d, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 108, false},
        {"Should Not Work 3", Argon2d, "", 1, 0, true},
        {"Should Work 6", Argon2, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 107, false},
        {"Should Not Work 6", Argon2, "", 1, 0, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHashWithType(rand.Reader, tt.password, tt.typ)
            hashSegments := strings.Split(got, "$")
            if (err != nil) != tt.wantErr {
                t.Errorf("GenerateSaltedHashWithType() = %v, want %v", err, tt.wantErr)
                return
            }

            if len(hashSegments) != tt.hashSegments {
                t.Errorf("GenerateSaltedHashWithType() had %d segments. Want %d", len(hashSegments), tt.hashSegments)
            }

            if len(got) != tt.hashLength {
                t.Errorf("GenerateSaltedHashWithType() hash length = %v, want %v", len(got), tt.hashLength)
            }
        })
    }
}

func Test_GenerateSaltedHashWithType_2(t *testing.T) {
    tests := []struct {
        name     string
        typ      Argon2Type
        password string
    }{
        {"Argon2id", Argon2id, "Password1"},
        {"Argon2i", Argon2i, "Password1"},
        {"Argon2d", Argon2d, `Password1`},
        {"Argon2", Argon2, `Password1`},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            hash, err := GenerateSaltedHashWithType(rand.Reader, tt.password, tt.typ)
            if err != nil {
                t.Errorf("GenerateSaltedHashWithType() err = %v", err)
                return
            }

            check, _ := CompareHashWithPassword(hash, tt.password)
            if !check {
                t.Error("CompareHashWithPassword() fail")
            }
        })
    }
}
