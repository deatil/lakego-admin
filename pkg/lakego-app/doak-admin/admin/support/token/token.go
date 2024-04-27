package token

import (
    "os"
    "sync"
    "time"
    "errors"

    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"

    "github.com/deatil/lakego-jwt/jwt"
    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/array"
)

type (
    // 配置
    ConfigMap = map[string]any

    // 载荷
    ClaimMap = map[string]any
)

/**
 * 授权
 *
 * @create 2021-6-19
 * @author deatil
 */
type Token struct {
    // 锁定
    mu sync.RWMutex

    // jwt
    JWT *jwt.JWT

    // 配置
    Config ConfigMap

    // 载荷
    Claims ClaimMap
}

// 授权结构体
func New(j *jwt.JWT) *Token {
    return &Token{
        JWT: j,
        Config: make(ConfigMap),
        Claims: make(ClaimMap),
    }
}

/**
 * 批量设置配置
 */
func (this *Token) WithConfig(configs ConfigMap) *Token {
    if len(configs) > 0 {
        for k, v := range configs {
            this.SetConfig(k, v)
        }
    }

    return this
}

/**
 * 设置配置
 */
func (this *Token) SetConfig(key string, value any) *Token {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.Config[key] = value

    return this
}

/**
 * 获取配置
 */
func (this *Token) GetConfig(key string) any {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return array.ArrGet(this.Config, key)
}

/**
 * 获取配置
 */
func (this *Token) GetStringConfig(key string, defVal string) string {
    conf := this.GetConfig(key)
    if conf == nil {
        return defVal
    }

    return conf.(string)
}

/**
 * 获取配置
 */
func (this *Token) GetIntConfig(key string, defVal int) int {
    conf := this.GetConfig(key)
    if conf == nil {
        return defVal
    }

    return conf.(int)
}

/**
 * 获取鉴权 token 过期时间
 */
func (this *Token) GetAccessExpiresIn() int {
    // 过期时间
    time := this.GetIntConfig("passport.access-expires-in", 0)

    return time
}

/**
 * 获取刷新 token 过期时间
 */
func (this *Token) GetRefreshExpiresIn() int {
    // 过期时间
    time := this.GetIntConfig("passport.refresh-expires-in", 0)

    return time
}

// 设置自定义载荷
func (this *Token) WithClaim(key string, value any) *Token {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.Claims[key] = value

    return this
}

/**
 * 生成鉴权 token
 */
func (this *Token) MakeJWT() *jwt.JWT {
    aud := this.GetStringConfig("jwt.aud", "")
    iss := this.GetStringConfig("jwt.iss", "")
    sub := this.GetStringConfig("jwt.sub", "")
    jti := this.GetStringConfig("jwt.jti", "")
    exp := this.GetIntConfig("jwt.exp", 0)
    nbf := this.GetIntConfig("jwt.nbf", 0)

    signingMethod := this.GetStringConfig("jwt.signing-method", "")
    secret := this.GetStringConfig("jwt.secret", "")
    privateKey := this.GetStringConfig("jwt.private-key", "")
    publicKey := this.GetStringConfig("jwt.public-key", "")
    privateKeyPassword := this.GetStringConfig("jwt.private-key-password", "")

    // 解析 base64
    secret = base64Decode(secret)

    // 格式化公钥和私钥
    privateKey = this.FormatPath(privateKey)
    publicKey = this.FormatPath(publicKey)

    // 读取文件
    privateKeyData, _ := this.ReadDataFromFile(privateKey)
    publicKeyData, _ := this.ReadDataFromFile(publicKey)

    // 私钥密码
    privateKeyPassword = base64Decode(privateKeyPassword)

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
        WithPrivateKey(privateKeyData).
        WithPublicKey(publicKeyData).
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
func (this *Token) MakeToken(claims map[string]string) (token string, err error) {
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
func (this *Token) MakeAccessToken(claims map[string]string) (token string, err error) {
    jti := this.GetStringConfig("passport.access-token-id", "")
    exp := this.GetAccessExpiresIn()

    passphraseIv := this.GetStringConfig("jwt.passphrase-iv", "")
    passphrase := this.GetStringConfig("jwt.passphrase", "")
    passphrase = base64Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(int64(exp)).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = this.Encode(v, passphrase, passphraseIv)
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
func (this *Token) MakeRefreshToken(claims map[string]string) (token string, err error) {
    jti := this.GetStringConfig("passport.refresh-token-id", "")
    exp := this.GetRefreshExpiresIn()

    passphraseIv := this.GetStringConfig("jwt.passphrase-iv", "")
    passphrase := this.GetStringConfig("jwt.passphrase", "")
    passphrase = base64Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(int64(exp)).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = this.Encode(v, passphrase, passphraseIv)
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
func (this *Token) GetAccessTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetStringConfig("passport.access-token-id", "")

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
func (this *Token) GetRefreshTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetStringConfig("passport.refresh-token-id", "")

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
func (this *Token) GetAccessTokenData(token string, key string, verify ...bool) string {
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
func (this *Token) GetRefreshTokenData(token string, key string, verify ...bool) string {
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
func (this *Token) GetFromTokenClaims(claims jwt.MapClaims, key string) any {
    if _, ok := claims[key]; !ok {
        return nil
    }

    return claims[key]
}

/**
 * 从 TokenClaims 获取数据
 */
func (this *Token) GetDataFromTokenClaims(claims jwt.MapClaims, key string) string {
    if _, ok := claims[key]; !ok {
        return ""
    }

    data := claims[key].(string)

    passphraseIv := this.GetStringConfig("jwt.passphrase-iv", "")
    passphrase := this.GetStringConfig("jwt.passphrase", "")
    passphrase = base64Decode(passphrase)

    if passphrase != "" {
        data = this.Decode(data, passphrase, passphraseIv)
    }

    return data
}

// 加密
func (this *Token) Encode(data string, passphrase string, iv string) string {
    data = crypto.
        FromString(data).
        SetIv(iv).
        SetKey(passphrase).
        Aes().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    return data
}

// 解密
func (this *Token) Decode(data string, passphrase string, iv string) string {
    data = crypto.
        FromBase64String(data).
        SetIv(iv).
        SetKey(passphrase).
        Aes().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    return data
}

// 从文件读取数据
func (this *Token) ReadDataFromFile(file string) ([]byte, error) {
    if !this.FileExist(file) {
        return []byte(""), errors.New("秘钥或者私钥文件不存在")
    }

    // 获取秘钥数据
    return os.ReadFile(file)
}

// 文件判断
func (this *Token) FileExist(fp string) bool {
    _, err := os.Stat(fp)
    return err == nil || os.IsExist(err)
}

// 格式化文件路径
func (this *Token) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}

func base64Decode(data string) string {
    return encoding.FromString(data).Base64Decode().ToString()
}
