package secp256k1

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/asn1"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "testing"
)

var publicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type ecPrivateKey struct {
    Version       int
    PrivateKey    []byte
    NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
    PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type keyMeta struct {
    KeyType       asn1.ObjectIdentifier
    NamedCurveOID asn1.ObjectIdentifier
}

type ecPublicKey struct {
    KeyMeta   keyMeta
    PublicKey asn1.BitString
}

type signature struct {
    R *big.Int
    S *big.Int
}

func TestVerify_OpenSSL(t *testing.T) {
    // integration test with OpenSSL
    // generate signature using OpenSSL, and verify it using goat.
    checkSecp256k1Support(t)

    for i := 0; i < 1024; i++ {
        t.Run(strconv.Itoa(i), testVerifyOpenSSL)
    }
}

func TestSign_OpenSSL(t *testing.T) {
    // integration test with OpenSSL
    // generate signature using goat, and verify it using OpenSSL.
    checkSecp256k1Support(t)

    for i := 0; i < 1024; i++ {
        t.Run(strconv.Itoa(i), testSignOpenSSL)
    }
}

func testVerifyOpenSSL(t *testing.T) {
    dir := t.TempDir()

    // generate a private key
    priv, err := ecdsa.GenerateKey(Curve(), rand.Reader)
    if err != nil {
        t.Error(err)
        return
    }
    privkeyPath := filepath.Join(dir, "privkey.pem")
    if err := writePrivKey(privkeyPath, priv); err != nil {
        t.Error(err)
        return
    }

    // generate a message
    message := make([]byte, 32)
    if _, err := rand.Read(message); err != nil {
        t.Error(err)
        return
    }
    messagePath := filepath.Join(dir, "message.txt")
    if err := os.WriteFile(messagePath, message, 0o644); err != nil {
        t.Error(err)
        return
    }

    // sign
    r, s, err := signWithOpenSSL(privkeyPath, messagePath)
    if err != nil {
        t.Error(err)
        return
    }

    sum := sha256.Sum256(message)
    if !ecdsa.Verify(&priv.PublicKey, sum[:], r, s) {
        t.Errorf("verify failed:\n"+
            "message: %x\n"+
            "X: %x\n"+
            "Y: %x\n"+
            "D: %x\n"+
            "R: %x\n"+
            "S: %x", message, priv.X, priv.Y, priv.D, r, s)
    }
}

func testSignOpenSSL(t *testing.T) {
    dir := t.TempDir()

    // generate a private key
    priv, err := ecdsa.GenerateKey(Curve(), rand.Reader)
    if err != nil {
        t.Error(err)
        return
    }
    pubkeyPath := filepath.Join(dir, "pubkey.pem")
    if err := writePubKey(pubkeyPath, &priv.PublicKey); err != nil {
        t.Error(err)
        return
    }

    // generate a message
    message := make([]byte, 32)
    if _, err := rand.Read(message); err != nil {
        t.Error(err)
        return
    }
    messagePath := filepath.Join(dir, "message.txt")
    if err := os.WriteFile(messagePath, message, 0o644); err != nil {
        t.Error(err)
        return
    }

    // calculate signature
    sum := sha256.Sum256(message)
    r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
    if err != nil {
        t.Error(err)
        return
    }
    signaturePath := filepath.Join(dir, "message.sig")
    if err := writeSignature(signaturePath, r, s); err != nil {
        t.Error(err)
        return
    }

    // verify
    if err := verifyWithOpenSSL(pubkeyPath, signaturePath, messagePath); err != nil {
        t.Errorf("verify failed: %v\n"+
            "message: %x\n"+
            "X: %x\n"+
            "Y: %x\n"+
            "D: %x\n"+
            "R: %x\n"+
            "S: %x", err, message, priv.X, priv.Y, priv.D, r, s)
    }
}

func checkSecp256k1Support(t *testing.T) bool {
    out, err := exec.Command("openssl", "ecparam", "-list_curves").CombinedOutput()
    if err != nil {
        t.Skip(err)
        return false
    }
    idx := bytes.Index(out, []byte("secp256k1"))
    if idx < 0 {
        t.Skip("OpenSSL doesn't support secp256k1")
        return false
    }
    return true
}

func signWithOpenSSL(privkeyPath, messagePath string) (r, s *big.Int, err error) {
    out, err := exec.Command("openssl", "dgst", "-sha256", "-sign", privkeyPath, messagePath).CombinedOutput()
    if err != nil {
        return nil, nil, fmt.Errorf("%w: %s", err, out)
    }

    var sig signature
    _, err = asn1.Unmarshal(out, &sig)
    if err != nil {
        return nil, nil, err
    }
    return sig.R, sig.S, nil
}

func verifyWithOpenSSL(pubkeyPath, signaturePath, messagePath string) error {
    out, err := exec.Command("openssl", "dgst", "-sha256", "-verify", pubkeyPath, "-signature", signaturePath, messagePath).CombinedOutput()
    if err != nil {
        return fmt.Errorf("%w: %s", err, out)
    }
    return nil
}

func writePrivKey(name string, key *ecdsa.PrivateKey) error {
    d := key.D.Bytes()
    size := (key.Params().BitSize + 7) / 8
    buf := make([]byte, 1+size*2)
    buf[0] = 0x04 // uncompressed point
    key.X.FillBytes(buf[1 : 1+size])
    key.Y.FillBytes(buf[1+size:])

    priv := ecPrivateKey{
        Version:       1,
        PrivateKey:    d,
        NamedCurveOID: curveOID,
        PublicKey: asn1.BitString{
            Bytes: buf,
        },
    }
    data, err := asn1.Marshal(priv)
    if err != nil {
        return err
    }
    pemData := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: data,
    })
    return os.WriteFile(name, pemData, 0o644)
}

func writePubKey(name string, key *ecdsa.PublicKey) error {
    size := (key.Params().BitSize + 7) / 8
    buf := make([]byte, 1+size*2)
    buf[0] = 0x04 // uncompressed point
    key.X.FillBytes(buf[1 : 1+size])
    key.Y.FillBytes(buf[1+size:])

    pub := ecPublicKey{
        KeyMeta: keyMeta{
            KeyType:       publicKeyOID,
            NamedCurveOID: curveOID,
        },
        PublicKey: asn1.BitString{
            Bytes: buf,
        },
    }
    data, err := asn1.Marshal(pub)
    if err != nil {
        return err
    }
    pemData := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: data,
    })
    return os.WriteFile(name, pemData, 0o644)
}

func writeSignature(name string, r, s *big.Int) error {
    sig := signature{
        R: r,
        S: s,
    }
    data, err := asn1.Marshal(sig)
    if err != nil {
        return err
    }
    return os.WriteFile(name, data, 0o644)
}
