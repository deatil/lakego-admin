package jwt

import (
    "time"
    "errors"

    "github.com/golang-jwt/jwt/v4"
)

// JWT
func New() *JWT {
    jwter := &JWT{
        Secret: "123456",
        SigningMethod: "HS256",
        Headers: make(HeaderMap),
        Claims: make(ClaimMap),
        SigningMethods: make(SigningMethodMap),
        SigningFuncs: make(SigningFuncMap),
        ParseFuncs: make(ParseFuncMap),
    }

    // 设置签名方式
    jwter.WithSignMethodMany(signingMethodList)

    return jwter
}

// jwt 默认
type (
    // 载荷
    Claims = jwt.Claims

    // 已注册载荷
    RegisteredClaims = jwt.RegisteredClaims

    // StandardClaims
    StandardClaims = jwt.StandardClaims

    // 载荷 map
    MapClaims = jwt.MapClaims

    // Token
    Token = jwt.Token

    // Keyfunc
    Keyfunc = jwt.Keyfunc

    // ClaimStrings
    ClaimStrings = jwt.ClaimStrings

    // NumericDate
    NumericDate = jwt.NumericDate

    // 签名方法
    SigningMethod = jwt.SigningMethod

    // 解析
    Parser = jwt.Parser
)

// TimeFunc = time.Now
var TimeFunc = jwt.TimeFunc

// 注册签名方法
// RegisterSigningMethod(alg string, f func() SigningMethod)
var RegisterSigningMethod = jwt.RegisterSigningMethod

// 获取注册的方法
// GetSigningMethod(alg string) (method SigningMethod)
var GetSigningMethod = jwt.GetSigningMethod

// 验证方式列表
var signingMethodList = map[string]jwt.SigningMethod {
    // Hmac
    "HS256": jwt.SigningMethodHS256,
    "HS384": jwt.SigningMethodHS384,
    "HS512": jwt.SigningMethodHS512,

    // RSA
    "RS256": jwt.SigningMethodRS256,
    "RS384": jwt.SigningMethodRS384,
    "RS512": jwt.SigningMethodRS512,

    // PSS
    "PS256": jwt.SigningMethodPS256,
    "PS384": jwt.SigningMethodPS384,
    "PS512": jwt.SigningMethodPS512,

    // ECDSA
    "ES256": jwt.SigningMethodES256,
    "ES384": jwt.SigningMethodES384,
    "ES512": jwt.SigningMethodES512,

    // EdDSA
    "EdDSA": jwt.SigningMethodEdDSA,
}

type (
    // jwt 头数据
    HeaderMap = map[string]interface{}

    // jwt 载荷
    ClaimMap = map[string]interface{}

    // 验证方式列表
    SigningMethodMap = map[string]jwt.SigningMethod

    // 自定义签名方式
    SigningFuncMap = map[string]func(*JWT) (interface{}, error)

    // 自定义解析方式
    ParseFuncMap = map[string]func(*JWT) (interface{}, error)

    // jwt 解析后的头数据 map
    ParsedHeaderMap = map[string]interface{}
)

/**
 * JWT
 *
 * @create 2021-9-15
 * @author deatil
 */
type JWT struct {
    // 头数据
    Headers HeaderMap

    // 载荷
    Claims ClaimMap

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
    SigningMethods SigningMethodMap

    // 自定义签名方式
    SigningFuncs SigningFuncMap

    // 自定义解析方式
    ParseFuncs ParseFuncMap
}

// (Issuer) 签发者
func (this *JWT) WithIss(iss string) *JWT {
    this.Claims["iss"] = iss
    return this
}

// (Issued At) 签发时间，unix时间戳
func (this *JWT) WithIat(iat int64) *JWT {
    this.Claims["iat"] = iat
    return this
}

// (Expiration Time) 过期时间，unix时间戳
func (this *JWT) WithExp(exp int64) *JWT {
    this.Claims["exp"] = time.Now().Add(time.Second * time.Duration(exp)).Unix()
    return this
}

// (Audience) 接收方
func (this *JWT) WithAud(aud string) *JWT {
    this.Claims["aud"] = aud
    return this
}

// (Subject) 主题
func (this *JWT) WithSub(sub string) *JWT {
    this.Claims["sub"] = sub
    return this
}

// (JWT ID) 唯一ID
func (this *JWT) WithJti(jti string) *JWT {
    this.Claims["jti"] = jti
    return this
}

// (Not Before) 不要早于这个时间
func (this *JWT) WithNbf(nbf int64) *JWT {
    this.Claims["nbf"] = time.Now().Add(time.Second * time.Duration(nbf)).Unix()
    return this
}

// 自定义载荷
func (this *JWT) WithClaim(key string, value interface{}) *JWT {
    this.Claims[key] = value
    return this
}

// 自定义 Header
func (this *JWT) WithHeader(key string, value interface{}) *JWT {
    this.Headers[key] = value
    return this
}

// 验证方式
func (this *JWT) WithSigningMethod(method string) *JWT {
    this.SigningMethod = method
    return this
}

// 密码
func (this *JWT) WithSecret(secret string) *JWT {
    this.Secret = secret
    return this
}

// 私钥
func (this *JWT) WithPrivateKey(privateKey string) *JWT {
    this.PrivateKey = privateKey
    return this
}

// 公钥
func (this *JWT) WithPublicKey(publicKey string) *JWT {
    this.PublicKey = publicKey
    return this
}

// 私钥密码
func (this *JWT) WithPrivateKeyPassword(password string) *JWT {
    this.PrivateKeyPassword = password
    return this
}

// 签名方式
func (this *JWT) WithSignMethod(name string, method jwt.SigningMethod) *JWT {
    if _, ok := this.SigningMethods[name]; ok {
        delete(this.SigningMethods, name)
    }

    this.SigningMethods[name] = method

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
    if _, ok := this.SigningMethods[name]; ok {
        delete(this.SigningMethods, name)
        return true
    }

    return false
}

// 自定义签名方式
func (this *JWT) WithSigningFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.SigningFuncs[name]; ok {
        delete(this.SigningFuncs, name)
    }

    this.SigningFuncs[name] = f

    return this
}

// 批量设置自定义签名方式
func (this *JWT) WithSigningFuncMany(funcs SigningFuncMap) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithSigningFunc(k, v)
        }
    }

    return this
}

// 移除自定义签名方式
func (this *JWT) WithoutSigningFunc(name string) bool {
    if _, ok := this.SigningFuncs[name]; ok {
        delete(this.SigningFuncs, name)

        return true
    }

    return false
}

// 自定义解析方式
func (this *JWT) WithParseFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.ParseFuncs[name]; ok {
        delete(this.ParseFuncs, name)
    }

    this.ParseFuncs[name] = f

    return this
}

// 批量设置自定义解析方式
func (this *JWT) WithParseFuncMany(funcs ParseFuncMap) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithParseFunc(k, v)
        }
    }

    return this
}

// 移除自定义解析方式
func (this *JWT) WithoutParseFunc(name string) bool {
    if _, ok := this.ParseFuncs[name]; ok {
        delete(this.ParseFuncs, name)

        return true
    }

    return false
}

// 生成token
func (this *JWT) MakeToken() (token string, err error) {
    var signingMethod jwt.SigningMethod
    if method, ok := this.SigningMethods[this.SigningMethod]; ok {
        signingMethod = method
    } else {
        signingMethod = jwt.SigningMethodHS256
    }

    // 签发时间没设置时重新设置
    if this.Claims["iat"] == "" {
        this.Claims["iat"] = time.Now().Unix()
    }

    // 载荷
    claims := make(jwt.MapClaims)
    if len(this.Claims) > 0 {
        for k, v := range this.Claims {
            claims[k] = v
        }
    }

    jwtToken := jwt.NewWithClaims(signingMethod, claims)

    // 设置自定义 Header
    if len(this.Headers) > 0 {
        for k2, v2 := range this.Headers {
            jwtToken.Header[k2] = v2
        }
    }

    // 密码
    var secret interface{}

    // 判断类型
    switch this.SigningMethod {
        // Hmac
        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := this.Secret
            if hmacSecret == "" {
                err = errors.New("Hmac 密码内容不能为空")
                return
            }

            secret = []byte(hmacSecret)

        // RSA
        case "RS256", "RS384", "RS512":
            // 获取秘钥数据
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("RSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            if this.PrivateKeyPassword != "" {
                secret, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyByte, this.PrivateKeyPassword)
            } else {
                secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyByte)
            }

            if err != nil {
                return
            }

        // PSS
        case "PS256", "PS384", "PS512":
            // 秘钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("PSS 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // ECDSA
        case "ES256", "ES384", "ES512":
            // 私钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("ECDSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseECPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // EdDSA
        case "EdDSA":
            // 私钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("EdDSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseEdPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // 默认先检查自定义签名方式
        default:
            // 检查自定义签名
            f, ok := this.SigningFuncs[this.SigningMethod]
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
        // Hmac
        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := this.Secret
            if hmacSecret == "" {
                err = errors.New("Hmac 密码错误或者为空")
                return nil, err
            }

            secret = []byte(hmacSecret)

        // RSA
        case "RS256", "RS384", "RS512":
            // 公钥
            keyData := this.PublicKey
            if keyData == "" {
                err = errors.New("RSA 公钥内容不能为空")
                return nil, err
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // PSS
        case "PS256", "PS384", "PS512":
            // 公钥
            keyData := this.PublicKey
            if keyData == "" {
                err = errors.New("PSS 公钥内容不能为空")
                return nil, err
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // ECDSA
        case "ES256", "ES384", "ES512":
            // 公钥
            keyData := this.PublicKey
            if keyData == "" {
                err = errors.New("ECDSA 公钥内容不能为空")
                return nil, err
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseECPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // EdDSA
        case "EdDSA":
            // 公钥
            keyData := this.PublicKey
            if keyData == "" {
                err = errors.New("EdDSA 公钥内容不能为空")
                return nil, err
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseEdPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // 默认检查自定义解析方式
        default:
            // 检查自定义解析
            f, ok := this.ParseFuncs[this.SigningMethod]
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

// 从 token 获取解析后的[载荷]数据
func (this *JWT) GetClaimsFromToken(token *jwt.Token) (jwt.MapClaims, error) {
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("Token 载荷获取失败")
    }

    return claims, nil
}

// 从 token 获取解析后的[Header]数据
func (this *JWT) GetHeadersFromToken(token *jwt.Token) (ParsedHeaderMap, error) {
    headers := token.Header
    if len(headers) == 0 {
        return nil, errors.New("Token 的 Header 获取失败")
    }

    return headers, nil
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

    if this.Claims["aud"] == "" || claims.VerifyAudience(this.Claims["aud"].(string), false) == false {
        return false, errors.New("Audience 验证失败")
    }

    if this.Claims["iss"] == "" || claims.VerifyIssuer(this.Claims["iss"].(string), false) == false {
        return false, errors.New("Issuer 验证失败")
    }

    return true, nil
}
