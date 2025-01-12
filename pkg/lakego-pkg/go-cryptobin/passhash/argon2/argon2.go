package argon2

import (
    "io"
    "fmt"
    "errors"
    "runtime"
    "strconv"
    "strings"
    "crypto/subtle"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/kdf/argon2"
)

// Argon2 Type enum
type Argon2Type uint

func (typ Argon2Type) String() string {
    switch typ {
        case Argon2d:
            return "argon2d"
        case Argon2i:
            return "argon2i"
        case Argon2id:
            return "argon2id"
        case Argon2:
            return "argon2"
        default:
            return "unknown type " + strconv.Itoa(int(typ))
    }
}

const (
    Argon2d Argon2Type = iota
    Argon2i
    Argon2id
    Argon2
)

// Argon2 options
type Opts struct {
    SaltLen int
    Time    uint32
    Memory  uint32
    Threads uint8
    KeyLen  uint32
}

var (
    // default Type
    defaultType = Argon2id

    // default Options
    defaultOpts = Opts{
        SaltLen: 32,
        Time:    1,
        Memory:  64 * 1024,
        Threads: uint8(runtime.NumCPU()),
        KeyLen:  32,
    }
)

// Generate Salted Hash
func GenerateSaltedHash(random io.Reader, password string) (string, error) {
    return GenerateSaltedHashWithTypeAndOpts(random, password, defaultType, defaultOpts)
}

// Generate Salted Hash with type
func GenerateSaltedHashWithType(random io.Reader, password string, typ Argon2Type) (string, error) {
    return GenerateSaltedHashWithTypeAndOpts(random, password, typ, defaultOpts)
}

// Generate Salted Hash with type and opts
func GenerateSaltedHashWithTypeAndOpts(random io.Reader, password string, typ Argon2Type, opt Opts) (string, error) {
    if len(password) == 0 {
        return "", errors.New("go-cryptobin/argon2: Password length cannot be 0")
    }

    saltLen       := opt.SaltLen
    argon2Time    := opt.Time
    argon2Memory  := opt.Memory
    argon2Threads := opt.Threads
    argon2KeyLen  := opt.KeyLen

    salt, _ := generateSalt(random, saltLen)

    var unencodedPassword []byte
    switch typ {
        case Argon2id:
            unencodedPassword = argon2.IDKey(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        case Argon2i, Argon2:
            unencodedPassword = argon2.Key(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        case Argon2d:
            unencodedPassword = argon2.DKey(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        default:
            return "", errors.New("go-cryptobin/argon2: Invalid Hash Type")
    }

    encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
    encodedPassword := base64.RawStdEncoding.EncodeToString(unencodedPassword)

    hash := fmt.Sprintf(
        "%s$%d$%d$%d$%d$%s$%s",
        typ, argon2.Version,
        argon2Memory, argon2Time, argon2Threads,
        encodedSalt, encodedPassword,
    )

    return hash, nil
}

// Compare Hash With Password
func CompareHashWithPassword(hash, password string) (bool, error) {
    if len(hash) == 0 || len(password) == 0 {
        return false, errors.New("go-cryptobin/argon2: Arguments cannot be zero length")
    }

    hashParts := strings.Split(hash, "$")
    if len(hashParts) != 7 {
        return false, errors.New("go-cryptobin/argon2: Invalid Data Len")
    }

    passwordType := hashParts[0]
    version, _ := strconv.Atoi(hashParts[1])

    memory, _ := strconv.Atoi(hashParts[2])
    time, _ := strconv.Atoi((hashParts[3]))
    threads, _ := strconv.Atoi(hashParts[4])

    salt, _ := base64.RawStdEncoding.DecodeString(hashParts[5])
    key, _ := base64.RawStdEncoding.DecodeString(hashParts[6])

    keyLen := len(key)

    if version != argon2.Version {
        return false, errors.New("go-cryptobin/argon2: Invalid Password Hash version")
    }

    var calculatedKey []byte
    switch passwordType {
        case "argon2id":
            calculatedKey = argon2.IDKey(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        case "argon2i", "argon2":
            calculatedKey = argon2.Key(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        case "argon2d":
            calculatedKey = argon2.DKey(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        default:
            return false, errors.New("go-cryptobin/argon2: Invalid Password Hash")
    }

    if subtle.ConstantTimeCompare(key, calculatedKey) != 1 {
        return false, errors.New("go-cryptobin/argon2: Password did not match")
    }

    return true, nil
}

// generate salt with length
func generateSalt(random io.Reader, length int) ([]byte, error) {
    salt := make([]byte, length)
    _, err := io.ReadFull(random, salt)
    if err != nil {
        return nil, err
    }

    return salt, nil
}
