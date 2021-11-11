package jwt

import (
    "os"
    "time"
    "errors"
    "github.com/golang-jwt/jwt/v4"

    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/support/base64"
)

// JWT
func New() *JWT {
    jwter := &JWT{
        Secret: "123456",
        SigningMethod: "HS256",
        Claims: make(Claims),
        SigningMethodList: make(SigningMethodMap),
        SigningFunc: make(SigningFunc),
        ParseFunc: make(ParseFunc),
    }

    // 设置签名方式
    jwter.WithSignMethodMany(signingMethodList)

    return jwter
}

// 验证方式列表
var signingMethodList = SigningMethodMap {
    "ES256": jwt.SigningMethodES256,
    "ES384": jwt.SigningMethodES384,
    "ES512": jwt.SigningMethodES512,

    "HS256": jwt.SigningMethodHS256,
    "HS384": jwt.SigningMethodHS384,
    "HS512": jwt.SigningMethodHS512,

    "RS256": jwt.SigningMethodRS256,
    "RS384": jwt.SigningMethodRS384,
    "RS512": jwt.SigningMethodRS512,

    "PS256": jwt.SigningMethodPS256,
    "PS384": jwt.SigningMethodPS384,
    "PS512": jwt.SigningMethodPS512,

    "EdDSA": jwt.SigningMethodEdDSA,
}

type (
    // jwt 载荷
    Claims map[string]interface{}

    // 验证方式列表
    SigningMethodMap map[string]jwt.SigningMethod

    // 自定义签名方式
    SigningFunc map[string]func(*JWT) (interface{}, error)

    // 自定义解析方式
    ParseFunc map[string]func(*JWT) (interface{}, error)
)

/**
 * JWT
 *
 * @create 2021-9-15
 * @author deatil
 */
type JWT struct {
    // 载荷
    Claims Claims

    // 签名方法
    SigningMethod string

    // 秘钥
    Secret string

    // 私钥
    PrivateKey string

    // 公钥
    PublicKey string

    // 私钥密码
    PrivateKeyPassword string

    // 验证方式列表
    SigningMethodList SigningMethodMap

    // 自定义签名方式
    SigningFunc SigningFunc

    // 自定义解析方式
    ParseFunc ParseFunc
}

// Audience
func (this *JWT) WithAud(aud string) *JWT {
    this.Claims["aud"] = aud
    return this
}

// ExpiresAt
func (this *JWT) WithExp(exp int64) *JWT {
    this.Claims["exp"] = time.Now().Add(time.Second * time.Duration(exp)).Unix()
    return this
}

// Id
func (this *JWT) WithJti(jti string) *JWT {
    this.Claims["jti"] = jti
    return this
}

// Issuer
func (this *JWT) WithIss(iss string) *JWT {
    this.Claims["iss"] = iss
    return this
}

// NotBefore
func (this *JWT) WithNbf(nbf int64) *JWT {
    this.Claims["nbf"] = time.Now().Add(time.Second * time.Duration(nbf)).Unix()
    return this
}

// Subject
func (this *JWT) WithSub(sub string) *JWT {
    this.Claims["sub"] = sub
    return this
}

// 设置自定义载荷
func (this *JWT) WithClaim(key string, value interface{}) *JWT {
    this.Claims[key] = value
    return this
}

// 设置验证方式
func (this *JWT) WithSigningMethod(method string) *JWT {
    this.SigningMethod = method
    return this
}

// 设置秘钥
func (this *JWT) WithSecret(secret string) *JWT {
    this.Secret = secret
    return this
}

// 设置私钥
func (this *JWT) WithPrivateKey(privateKey string) *JWT {
    this.PrivateKey = privateKey
    return this
}

// 设置公钥
func (this *JWT) WithPublicKey(publicKey string) *JWT {
    this.PublicKey = publicKey
    return this
}

// 设置私钥密码
func (this *JWT) WithPrivateKeyPassword(password string) *JWT {
    this.PrivateKeyPassword = password
    return this
}

// 设置签名方式
func (this *JWT) WithSignMethod(name string, method jwt.SigningMethod) *JWT {
    if _, ok := this.SigningMethodList[name]; ok {
        delete(this.SigningMethodList, name)
    }

    this.SigningMethodList[name] = method

    return this
}

// 批量设置签名方式
func (this *JWT) WithSignMethodMany(methods SigningMethodMap) *JWT {
    if len(methods) > 0 {
        for k, v := range methods {
            this.WithSignMethod(k, v)
        }
    }

    return this
}

// 移除签名方式
func (this *JWT) WithoutSignMethod(name string) bool {
    if _, ok := this.SigningMethodList[name]; ok {
        delete(this.SigningMethodList, name)
        return true
    }

    return false
}

// 设置自定义签名方式
func (this *JWT) WithSigningFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.SigningFunc[name]; ok {
        delete(this.SigningFunc, name)
    }

    this.SigningFunc[name] = f

    return this
}

// 批量设置自定义签名方式
func (this *JWT) WithSigningFuncMany(funcs SigningFunc) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithSigningFunc(k, v)
        }
    }

    return this
}

// 移除自定义签名方式
func (this *JWT) WithoutSigningFunc(name string) bool {
    if _, ok := this.SigningFunc[name]; ok {
        delete(this.SigningFunc, name)

        return true
    }

    return false
}

// 设置自定义解析方式
func (this *JWT) WithParseFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.ParseFunc[name]; ok {
        delete(this.ParseFunc, name)
    }

    this.ParseFunc[name] = f

    return this
}

// 批量设置自定义解析方式
func (this *JWT) WithParseFuncMany(funcs ParseFunc) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithParseFunc(k, v)
        }
    }

    return this
}

// 移除自定义解析方式
func (this *JWT) WithoutParseFunc(name string) bool {
    if _, ok := this.ParseFunc[name]; ok {
        delete(this.ParseFunc, name)

        return true
    }

    return false
}

// 生成token
func (this *JWT) MakeToken() (token string, err error) {
    var signingMethod jwt.SigningMethod
    if method, ok := this.SigningMethodList[this.SigningMethod]; ok {
        signingMethod = method
    } else {
        signingMethod = jwt.SigningMethodHS256
    }

    // 载荷
    claims := make(jwt.MapClaims)
    if len(this.Claims) > 0 {
        for k, v := range this.Claims {
            claims[k] = v
        }
    }

    jwtToken := jwt.NewWithClaims(signingMethod, claims)

    // 返回 token
    token = ""

    // 密码
    var secret interface{}

    // 判断类型
    switch this.SigningMethod {
        case "RS256", "RS384", "RS512":
            // 获取秘钥数据
            keyData, e := this.ReadDataFromFile(this.PrivateKey)

            if e != nil {
                err = errors.New("RSA 私钥不存在或者错误")
                return
            }

            if this.PrivateKeyPassword != "" {
                // 密码
                password := base64.Decode(this.PrivateKeyPassword)

                secret, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyData, password)
            } else {
                secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
            }

            if err != nil {
                return
            }

        case "PS256", "PS384", "PS512":
            // 秘钥
            keyData, e := this.ReadDataFromFile(this.PrivateKey)

            if e != nil {
                err = errors.New("PSS 私钥不存在或者错误")
                return
            }

            secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)

            if err != nil {
                return
            }

        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := base64.Decode(this.Secret)

            if hmacSecret == "" {
                err = errors.New("Hmac 密码错误或者为空")
                return
            }

            secret = []byte(hmacSecret)

        case "ES256", "ES384", "ES512":
            // 私钥
            keyData, e := this.ReadDataFromFile(this.PrivateKey)

            if e != nil {
                err = errors.New("ECDSA 私钥不存在或者错误")
                return
            }

            secret, err = jwt.ParseECPrivateKeyFromPEM(keyData)

            if err != nil {
                return
            }

        case "EdDSA":
            // 私钥
            keyData, e := this.ReadDataFromFile(this.PrivateKey)

            if e != nil {
                err = errors.New("EdDSA 私钥不存在或者错误")
                return
            }

            secret, err = jwt.ParseEdPrivateKeyFromPEM(keyData)

            if err != nil {
                return
            }

        default:
            // 自定义签名
            f, ok := this.SigningFunc[this.SigningMethod]
            if !ok {
                err = errors.New("签名类型错误")
                return
            }

            secret, err = f(this)

            if err != nil {
                return
            }

    }

    token, err = jwtToken.SignedString(secret)
    return
}

// 解析 token
func (this *JWT) ParseToken(strToken string) (*jwt.Token, error) {
    var err error
    var secret interface{}

    // 判断类型
    switch this.SigningMethod {
        case "RS256", "RS384", "RS512":
            // 公钥
            keyData, e := this.ReadDataFromFile(this.PublicKey)

            if e != nil {
                err = errors.New("RSA 公钥不存在或者错误")
                return nil, err
            }

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyData)

            if err != nil {
                return nil, err
            }

        case "PS256", "PS384", "PS512":
            // 公钥
            keyData, e := this.ReadDataFromFile(this.PublicKey)

            if e != nil {
                err = errors.New("PSS 公钥不存在或者错误")
                return nil, err
            }

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyData)

            if err != nil {
                return nil, err
            }

        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := base64.Decode(this.Secret)

            if hmacSecret == "" {
                err = errors.New("Hmac 密码错误或者为空")
                return nil, err
            }

            secret = []byte(hmacSecret)

        case "ES256", "ES384", "ES512":
            // 公钥
            keyData, e := this.ReadDataFromFile(this.PublicKey)

            if e != nil {
                err = errors.New("ECDSA 公钥不存在或者错误")
                return nil, err
            }

            secret, err = jwt.ParseECPublicKeyFromPEM(keyData)

            if err != nil {
                return nil, err
            }

        case "EdDSA":
            // 公钥
            keyData, e := this.ReadDataFromFile(this.PublicKey)

            if e != nil {
                err = errors.New("EdDSA 公钥不存在或者错误")
                return nil, err
            }

            secret, err = jwt.ParseEdPublicKeyFromPEM(keyData)

            if err != nil {
                return nil, err
            }

        default:
            // 自定义解析
            f, ok := this.ParseFunc[this.SigningMethod]
            if !ok {
                err = errors.New("签名类型错误")
                return nil, err
            }

            secret, err = f(this)

            if err != nil {
                return nil, err
            }

    }

    token, err := jwt.Parse(strToken, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })

    if err != nil {
        return nil, err
    }

    return token, nil
}

// 从 token 获取解析后的数据
func (this *JWT) GetClaimsFromToken(token *jwt.Token) (jwt.MapClaims, error) {
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("Token 载荷获取失败")
    }

    return claims, nil
}

// token 过期检测
func (this *JWT) Validate(token *jwt.Token) (bool, error) {
    if err := token.Claims.Valid(); err != nil {
        return false, err
    }

    return true, nil
}

// 验证 token 是否有效
func (this *JWT) Verify(token *jwt.Token) (bool, error) {
    claims, err := this.GetClaimsFromToken(token)
    if err != nil {
        return false, err
    }

    if claims.VerifyAudience(this.Claims["aud"].(string), false) == false {
        return false, errors.New("Audience 验证失败")
    }

    if claims.VerifyIssuer(this.Claims["iss"].(string), false) == false {
        return false, errors.New("Issuer 验证失败")
    }

    return true, nil
}

// 从文件读取数据
func (this *JWT) ReadDataFromFile(file string) ([]byte, error) {
    // 文件
    keyFile := this.FormatPath(file)

    if !this.FileExist(keyFile) {
        return nil, errors.New("秘钥或者私钥文件不存在")
    }

    // 获取秘钥数据
    return os.ReadFile(keyFile)
}

// 文件判断
func (this *JWT) FileExist(fp string) bool {
    _, err := os.Stat(fp)
    return err == nil || os.IsExist(err)
}

// 格式化文件路径
func (this *JWT) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
