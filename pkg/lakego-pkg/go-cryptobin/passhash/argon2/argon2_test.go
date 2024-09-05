package argon2

import (
    "strings"
    "testing"
)

func TestGenerateSaltedHash(t *testing.T) {
    tests := []struct {
        name         string
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", "Password1", 7, 111, false},
        {"Should Not Work", "", 1, 0, true},
        {"Should Work 2", "gS</5Tu>3@(<FCtY", 7, 111, false},
        {"Should Work 3", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 111, false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHash(tt.password)
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

func TestCompareHashWithPassword(t *testing.T) {
    tests := []struct {
        name     string
        hash     string
        password string
        isValid  bool
        wantErr  bool
    }{
        {"Should Work 1", `argon2id$1$65536$4$32$Kmmw5Rb2JicAHlGL+yIvE5AlamkCZimr9vEqqgxj4pU=$BJzVSk9azcO/6Po+x6qWwFUFZlBy9sUsp4eSDzv20sU=`, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, true, false},
        {"Should Not Work 1", `argon2id$1$65536$4$32$IJwacnund802ogLkPaNTHuspQBrAwKlySItlOcKvpaI=$eGVF7y4cyufIVajJFYf/yoRQp8BJS+Qplx5bYXSXX2A=`, `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, false, true},
        {"Should Not Work 2", ``, ``, false, true},
        {"Should Not Work 3", `badHash`, ``, false, true},
        {"Should Work 2", `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$oLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, true, false},
        {"Should Not Work 4", `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$XLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, false, true},
        {"Should Not Work 5", `argon2$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$XLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, false, true},
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

func TestGenerateSaltedHashWithType(t *testing.T) {
    tests := []struct {
        name         string
        typ          string
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", "argon2id", "Password1", 7, 111, false},
        {"Should Not Work", "argon2id", "", 1, 0, true},
        {"Should Work 2", "argon2id", "gS</5Tu>3@(<FCtY", 7, 111, false},
        {"Should Work 3", "argon2id", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 111, false},
        {"Should Work 31", "argon2i", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 7, 110, false},
        {"Should Not Work 2", "argon2i", "", 1, 0, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHashWithType(tt.password, tt.typ)
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
