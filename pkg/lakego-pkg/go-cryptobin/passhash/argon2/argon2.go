package argon2

import (
    "fmt"
    "errors"
    "runtime"
    "strconv"
    "strings"
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"

    "golang.org/x/crypto/argon2"
)

// 配置
type Opt struct {
    SaltLen int
    Time    uint32
    Memory  uint32
    Threads uint8
    KeyLen  uint32
}

var (
    // 默认类型
    defaultType = "argon2id"

    // 默认配置
    defaultOpt = Opt{
        SaltLen: 32,
        Time:    1,
        Memory:  64 * 1024,
        Threads: uint8(runtime.NumCPU()),
        KeyLen:  32,
    }
)

// 生成密钥
func GenerateSaltedHash(password string) (string, error) {
    return GenerateSaltedHashWithTypeAndOpt(password, defaultType, defaultOpt)
}

// 生成密钥带类型
func GenerateSaltedHashWithType(password string, typ string) (string, error) {
    return GenerateSaltedHashWithTypeAndOpt(password, typ, defaultOpt)
}

// 生成密钥带类型和设置
func GenerateSaltedHashWithTypeAndOpt(password string, typ string, opt Opt) (string, error) {
    if len(password) == 0 {
        return "", errors.New("Password length cannot be 0")
    }

    saltLen       := opt.SaltLen
    argon2Time    := opt.Time
    argon2Memory  := opt.Memory
    argon2Threads := opt.Threads
    argon2KeyLen  := opt.KeyLen

    salt, _ := generateSalt(saltLen)

    var unencodedPassword []byte
    switch typ {
        case "argon2id":
            unencodedPassword = argon2.IDKey(
                []byte(password), []byte(salt),
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        case "argon2i", "argon2":
            unencodedPassword = argon2.Key(
                []byte(password), []byte(salt),
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        default:
            return "", errors.New("Invalid Hash Type")
    }

    encodedPassword := base64.StdEncoding.EncodeToString(unencodedPassword)

    hash := fmt.Sprintf(
        "%s$%d$%d$%d$%d$%s$%s",
        typ, argon2Time,
        argon2Memory, argon2Threads,
        argon2KeyLen, salt,
        encodedPassword,
    )

    return hash, nil
}

// 验证密钥
func CompareHashWithPassword(hash, password string) (bool, error) {
    if len(hash) == 0 || len(password) == 0 {
        return false, errors.New("Arguments cannot be zero length")
    }

    hashParts := strings.Split(hash, "$")
    if len(hashParts) != 7 {
        return false, errors.New("Invalid Data Len")
    }

    passwordType := hashParts[0]
    time, _ := strconv.Atoi((hashParts[1]))
    memory, _ := strconv.Atoi(hashParts[2])
    threads, _ := strconv.Atoi(hashParts[3])
    keyLen, _ := strconv.Atoi(hashParts[4])
    salt := []byte(hashParts[5])
    key, _ := base64.StdEncoding.DecodeString(hashParts[6])

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
        default:
            return false, errors.New("Invalid Password Hash")
    }

    if subtle.ConstantTimeCompare(key, calculatedKey) != 1 {
        return false, errors.New("Password did not match")
    }

    return true, nil
}

func generateSalt(len int) (string, error) {
    unencodedSalt := make([]byte, len)

    if _, err := rand.Read(unencodedSalt); err != nil {
        return "", err
    }

    return base64.StdEncoding.EncodeToString(unencodedSalt), nil
}
