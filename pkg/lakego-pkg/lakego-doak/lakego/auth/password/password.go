package password

import (
    "github.com/deatil/go-hash/hash"

    "github.com/deatil/lakego-doak/lakego/random"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

// 生成密码，密码为 MD5 加密后
func MakePassword(password string) (string, string) {
    return EncryptPassword(password)
}

// 检测密码
func CheckPassword(password string, needPassword string, needSalt string) bool {
    encryptPassword := EncryptPasswordWithEncrypt(needPassword, needSalt)
    return password == encryptPassword
}

// 生成密码
func EncryptPassword(password string) (pass string, encrypt string) {
    encrypt = random.String(6)
    pass = EncryptPasswordWithEncrypt(password, encrypt);
    return
}

/**
 * 密码加密
 *
 * @param password 密码
 * @param encrypt 传入加密串，在修改密码时做认证
 * @return password, encrypt
 */
func EncryptPasswordWithEncrypt(password string, encrypt string) string {
    return hash.MD5(hash.MD5(password + encrypt) + GetPasswordSalt())
}

// 密码通用盐
func GetPasswordSalt() string {
    return config.New("auth").GetString("passport.password-salt")
}
