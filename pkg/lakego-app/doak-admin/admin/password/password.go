package password

import (
    "github.com/deatil/lakego-doak/lakego/random"
    "github.com/deatil/lakego-doak/lakego/facade"

    "github.com/deatil/lakego-doak-admin/admin/support/utils"
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

// 密码加密
func EncryptPasswordWithEncrypt(password string, encrypt string) string {
    return utils.MD5(utils.MD5(password + encrypt) + GetPasswordSalt())
}

// 密码通用盐
func GetPasswordSalt() string {
    return facade.Config("auth").GetString("passport.password-salt")
}
