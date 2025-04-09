package chaocipher

import (
    "testing"
)

func Test_Check(t *testing.T) {
    ciphertext := "OAHQHCNYNXTSZJRRHJBYHQKSOUJY"
    plaintext := "WELLDONEISBETTERTHANWELLSAID"

    encoded := StdEncoding.EncodeToString([]byte(plaintext))
    if ciphertext != encoded {
        t.Errorf("Encrypt error: act=%s, old=%s\n", encoded, ciphertext)
    }

    // ==========

    decoded, err := StdEncoding.DecodeString(ciphertext)
    if err != nil {
        t.Fatal(err)
    }

    if plaintext != string(decoded) {
        t.Errorf("Decrypt error: act=%s, old=%s\n", string(decoded), plaintext)
    }
}
