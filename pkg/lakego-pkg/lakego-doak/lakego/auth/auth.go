package auth

import (
    "os"
    "time"
    "errors"

    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/go-cryptobin/cryptobin"
    "github.com/deatil/lakego-jwt/jwt"
    "github.com/deatil/lakego-doak/lakego/path"
)

// 授权结构体
func New() *Auth {
    return &Auth{
        Config: make(ConfigMap),
        Claims: make(ClaimMap),
    }
}

// 加密向量
var cryptoIv = "hyju5yu7f0.gtr3e"

type (
    // 配置
    ConfigMap = map[string]interface{}

    // 载荷
    ClaimMap = map[string]interface{}
)

/**
 * 授权
 *
 * @create 2021-6-19
 * @author deatil
 */
type Auth struct {
    // jwt
    JWT *jwt.JWT

    // 配置
    Config ConfigMap

    // 载荷
    Claims ClaimMap
}

/**
 * 设置 JWT
 */
func (this *Auth) WithJWT(JWT *jwt.JWT) *Auth {
    this.JWT = JWT

    return this
}

/**
 * 获取设置的JWT
 */
func (this *Auth) GetJWT() *jwt.JWT {
    return this.JWT
}

/**
 * 设置配置
 */
func (this *Auth) WithConfig(key string, value interface{}) *Auth {
    this.Config[key] = value

    return this
}

/**
 * 批量设置配置
 */
func (this *Auth) WithConfigs(configs ConfigMap) *Auth {
    if len(configs) > 0 {
        for k, v := range configs {
            this.WithConfig(k, v)
        }
    }

    return this
}

/**
 * 获取配置
 */
func (this *Auth) GetConfig(key string) interface{} {
    return this.Config[key]
}

/**
 * 获取配置
 */
func (this *Auth) GetConfigFromMap(key string, key2 string) interface{} {
    // 配置
    conf := this.Config[key]
    if conf == "" {
        return nil
    }

    // 配置列表
    confMap := conf.(ConfigMap)

    // 过期时间
    conf2 := confMap[key2]
    if conf2 == "" {
        return nil
    }

    return conf2
}

/**
 * 获取配置
 */
func (this *Auth) GetStringConfig(key string, key2 string, defaultValue string) string {
    conf := this.GetConfigFromMap(key, key2)
    if conf == nil {
        return defaultValue
    }

    return conf.(string)
}

/**
 * 获取配置
 */
func (this *Auth) GetIntConfig(key string, key2 string, defaultValue int) int {
    conf := this.GetConfigFromMap(key, key2)
    if conf == nil {
        return defaultValue
    }

    return conf.(int)
}

/**
 * 获取鉴权 token 过期时间
 */
func (this *Auth) GetAccessExpiresIn() int {
    // 过期时间
    time := this.GetIntConfig("passport", "accessexpiresin", 0)

    return time
}

/**
 * 获取刷新 token 过期时间
 */
func (this *Auth) GetRefreshExpiresIn() int {
    // 过期时间
    time := this.GetIntConfig("passport", "refreshexpiresin", 0)

    return time
}

// 设置自定义载荷
func (this *Auth) WithClaim(key string, value interface{}) *Auth {
    this.Claims[key] = value
    return this
}

/**
 * 生成鉴权 token
 */
func (this *Auth) MakeJWT() *jwt.JWT {
    aud := this.GetStringConfig("jwt", "aud", "")
    iss := this.GetStringConfig("jwt", "iss", "")
    sub := this.GetStringConfig("jwt", "sub", "")
    jti := this.GetStringConfig("jwt", "jti", "")
    exp := this.GetIntConfig("jwt", "exp", 0)
    nbf := this.GetIntConfig("jwt", "nbf", 0)

    signingMethod := this.GetStringConfig("jwt", "signingmethod", "")
    secret := this.GetStringConfig("jwt", "secret", "")
    privateKey := this.GetStringConfig("jwt", "privatekey", "")
    publicKey := this.GetStringConfig("jwt", "publickey", "")
    privateKeyPassword := this.GetStringConfig("jwt", "privatekeypassword", "")

    // 解析 base64
    secret = encoding.Base64Decode(secret)

    // 格式化公钥和私钥
    privateKey = this.FormatPath(privateKey)
    publicKey = this.FormatPath(publicKey)

    // 读取文件
    privateKeyData, _ := this.ReadDataFromFile(privateKey)
    publicKeyData, _ := this.ReadDataFromFile(publicKey)

    // 私钥密码
    privateKeyPassword = encoding.Base64Decode(privateKeyPassword)

    nowTime := time.Now().Unix()

    jwtHandler := this.JWT.
        WithAud(aud).
        WithIat(nowTime).
        WithExp(int64(exp)).
        WithJti(jti).
        WithIss(iss).
        WithNbf(int64(nbf)).
        WithSub(sub).
        WithSigningMethod(signingMethod).
        WithSecret(secret).
        WithPrivateKey(string(privateKeyData)).
        WithPublicKey(string(publicKeyData)).
        WithPrivateKeyPassword(privateKeyPassword)

    if len(this.Claims) > 0 {
        for k, v := range this.Claims {
            jwtHandler.WithClaim(k, v)
        }
    }

    return jwtHandler
}

/**
 * 生成 token
 */
func (this *Auth) MakeToken(claims map[string]string) (token string, err error) {
    jwtHandle := this.MakeJWT()

    if len(claims) > 0 {
        for k, v := range claims {
            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 生成鉴权 token
 */
func (this *Auth) MakeAccessToken(claims map[string]string) (token string, err error) {
    jti := this.GetStringConfig("passport", "accesstokenid", "")
    exp := this.GetAccessExpiresIn()

    passphrase := this.GetStringConfig("jwt", "passphrase", "")
    passphrase = encoding.Base64Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(int64(exp)).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = this.Encode(v, passphrase)
            }

            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 生成刷新 token
 */
func (this *Auth) MakeRefreshToken(claims map[string]string) (token string, err error) {
    jti := this.GetStringConfig("passport", "refreshtokenid", "")
    exp := this.GetRefreshExpiresIn()

    passphrase := this.GetStringConfig("jwt", "passphrase", "")
    passphrase = encoding.Base64Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(int64(exp)).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = this.Encode(v, passphrase)
            }

            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 获取鉴权 token
 */
func (this *Auth) GetAccessTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetStringConfig("passport", "accesstokenid", "")

    jwter := this.MakeJWT().WithJti(jti)

    parsedToken, err := jwter.ParseToken(token)
    if err != nil {
        return nil, err
    }

    _, err2 := jwter.Validate(parsedToken)
    if err2 != nil {
        return nil, err2
    }

    // 检测
    isVerify := true
    if len(verify) > 0 {
        isVerify = verify[0]
    }

    if isVerify {
        _, err3 := jwter.Verify(parsedToken)
        if err3 != nil {
            return nil, err3
        }
    }

    claims, claimsErr := jwter.GetClaimsFromToken(parsedToken)
    if claimsErr != nil {
        return nil, claimsErr
    }

    return claims, nil
}

/**
 * 获取刷新 token
 */
func (this *Auth) GetRefreshTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetStringConfig("passport", "refreshtokenid", "")

    jwter := this.MakeJWT().WithJti(jti)

    parsedToken, err := jwter.ParseToken(token)
    if err != nil {
        return nil, err
    }

    _, err2 := jwter.Validate(parsedToken)
    if err2 != nil {
        return nil, err2
    }

    // 检测
    isVerify := true
    if len(verify) > 0 {
        isVerify = verify[0]
    }

    if isVerify {
        _, err3 := jwter.Verify(parsedToken)
        if err3 != nil {
            return nil, err3
        }
    }

    claims, claimsErr := jwter.GetClaimsFromToken(parsedToken)
    if claimsErr != nil {
        return nil, claimsErr
    }

    return claims, nil
}

/**
 * 获取鉴权 token 所在 userid
 */
func (this *Auth) GetAccessTokenData(token string, key string, verify ...bool) string {
    claims, err := this.GetAccessTokenClaims(token, verify...)
    if err != nil {
        return ""
    }

    data := this.GetDataFromTokenClaims(claims, key)

    return data
}

/**
 * 获取刷新 token 所在 userid
 */
func (this *Auth) GetRefreshTokenData(token string, key string, verify ...bool) string {
    claims, err := this.GetRefreshTokenClaims(token, verify...)
    if err != nil {
        return ""
    }

    data := this.GetDataFromTokenClaims(claims, key)

    return data

}

/**
 * 从 Claims 获取数据
 */
func (this *Auth) GetFromTokenClaims(claims jwt.MapClaims, key string) interface{} {
    if _, ok := claims[key]; !ok {
        return nil
    }

    return claims[key]
}

/**
 * 从 TokenClaims 获取数据
 */
func (this *Auth) GetDataFromTokenClaims(claims jwt.MapClaims, key string) string {
    if _, ok := claims[key]; !ok {
        return ""
    }

    data := claims[key].(string)

    passphrase := this.GetStringConfig("jwt", "passphrase", "")
    passphrase = encoding.Base64Decode(passphrase)

    if passphrase != "" {
        data = this.Decode(data, passphrase)
    }

    return data
}

// 加密
func (this *Auth) Encode(data string, passphrase string) string {
    data = cryptobin.
        FromString(data).
        SetIv(cryptoIv).
        SetKey(passphrase).
        Aes().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    return data
}

// 解密
func (this *Auth) Decode(data string, passphrase string) string {
    data = cryptobin.
        FromBase64String(data).
        SetIv(cryptoIv).
        SetKey(passphrase).
        Aes().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    return data
}

// 从文件读取数据
func (this *Auth) ReadDataFromFile(file string) ([]byte, error) {
    if !this.FileExist(file) {
        return []byte(""), errors.New("秘钥或者私钥文件不存在")
    }

    // 获取秘钥数据
    return os.ReadFile(file)
}

// 文件判断
func (this *Auth) FileExist(fp string) bool {
    _, err := os.Stat(fp)
    return err == nil || os.IsExist(err)
}

// 格式化文件路径
func (this *Auth) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
