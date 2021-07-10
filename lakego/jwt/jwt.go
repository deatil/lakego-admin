package jwt

import (
    "errors"
    "time"
    "io/ioutil"
    "github.com/dgrijalva/jwt-go"
)

// 验证方式列表
var signingMethodList = map[string]interface{} {
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
}

type JWT struct {
    Claims map[string]interface{}
    NewClaims map[string]interface{}
    
    SigningMethod string
    Secret string
    PrivateKey string
    PublicKey string
    PrivateKeyPassword string // 私钥密码
}

func New() *JWT {
    claim := make(map[string]interface{})
    newClaims := make(map[string]interface{})
    
    return &JWT{
        Secret: "123456",
        SigningMethod: "HS256",
        Claims: claim,
        NewClaims: newClaims,
    }
}

func (jwter *JWT) WithAud(aud string) *JWT {
    jwter.Claims["Audience"] = aud
    return jwter
}

func (jwter *JWT) WithExp(exp int64) *JWT {
    jwter.Claims["ExpiresAt"] = exp
    return jwter
}

func (jwter *JWT) WithJti(id string) *JWT {
    jwter.Claims["Id"] = id
    return jwter
}

func (jwter *JWT) WithIss(iss string) *JWT {
    jwter.Claims["Issuer"] = iss
    return jwter
}

func (jwter *JWT) WithNbf(nbf int64) *JWT {
    jwter.Claims["NotBefore"] = nbf
    return jwter
}

func (jwter *JWT) WithSub(sub string) *JWT {
    jwter.Claims["Subject"] = sub
    return jwter
}

// 设置自定义载荷
func (jwter *JWT) WithClaim(key string, value interface{}) *JWT {
    jwter.NewClaims[key] = value
    return jwter
}

// 设置验证方式
func (jwter *JWT) WithSigningMethod(method string) *JWT {
    jwter.SigningMethod = method
    return jwter
}

// 设置秘钥
func (jwter *JWT) WithSecret(secret string) *JWT {
    jwter.Secret = secret
    return jwter
}

// 设置私钥
func (jwter *JWT) WithPrivateKey(privateKey string) *JWT {
    jwter.PrivateKey = privateKey
    return jwter
}

// 设置公钥
func (jwter *JWT) WithPublicKey(publicKey string) *JWT {
    jwter.PublicKey = publicKey
    return jwter
}

// 设置私钥密码
func (jwter *JWT) WithPrivateKeyPassword(password string) *JWT {
    jwter.PrivateKeyPassword = password
    return jwter
}

// 生成token
func (jwter *JWT) MakeToken() (token string, err error) {
    claims := make(jwt.MapClaims)
    
    claims["iat"] = time.Now().Unix()
    if _, ok := jwter.Claims["Audience"]; ok {
        claims["aud"] = jwter.Claims["Audience"].(string)
    }
    if _, ok := jwter.Claims["ExpiresAt"]; ok {
        claims["exp"] = time.Now().Add(time.Second * time.Duration(jwter.Claims["ExpiresAt"].(int64))).Unix()
    }
    if _, ok := jwter.Claims["Id"]; ok {
        claims["jti"] = jwter.Claims["Id"].(string)
    }
    if _, ok := jwter.Claims["Issuer"]; ok {
        claims["iss"] = jwter.Claims["Issuer"].(string)
    }
    if _, ok := jwter.Claims["NotBefore"]; ok {
        claims["nbf"] = time.Now().Add(time.Second * time.Duration(jwter.Claims["NotBefore"].(int64))).Unix()
    }
    if _, ok := jwter.Claims["Subject"]; ok {
        claims["sub"] = jwter.Claims["Subject"].(string)
    }
    
    for k, v := range jwter.NewClaims {
        claims[k] = v
    }
    
    var methodType jwt.SigningMethod
    if method, ok := signingMethodList[jwter.SigningMethod]; !ok {
        methodType = method.(jwt.SigningMethod)
    } else {
        methodType = jwt.SigningMethodHS256
    }
    
    jwtToken := jwt.NewWithClaims(methodType, claims)
    
    var secret interface{}
    
    if jwter.SigningMethod == "RS256" || jwter.SigningMethod == "RS384" || jwter.SigningMethod == "RS512" {
        if jwter.PrivateKeyPassword != "" {
            if keyData, e := ioutil.ReadFile(jwter.PrivateKey); e == nil {
                secret, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyData, jwter.PrivateKeyPassword)
                
                if err != nil {
                    token = ""
                    return 
                }
            } else {
                token = ""
                err = errors.New("PrivateKey not exists")
                return 
            }
        } else {
            if keyData, e := ioutil.ReadFile(jwter.PrivateKey); e == nil {
                secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
                
                if err != nil {
                    token = ""
                    return 
                }
            } else {
                token = ""
                err = errors.New("PrivateKey not exists")
                return 
            }
        }
    } else if jwter.SigningMethod == "PS256" || jwter.SigningMethod == "PS384" || jwter.SigningMethod == "PS512" {
        if keyData, e := ioutil.ReadFile(jwter.PrivateKey); e == nil {
            secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
            
            if err != nil {
                token = ""
                return 
            }
        } else {
            token = ""
            err = errors.New("PrivateKey not exists")
            return 
        }
    } else if jwter.SigningMethod == "HS256" || jwter.SigningMethod == "HS384" || jwter.SigningMethod == "HS512" {
        if secretData, e := ioutil.ReadFile(jwter.Secret); e == nil {
            secret = secretData
        } else {
            secret = []byte(jwter.Secret)
        }
    } else if jwter.SigningMethod == "ES256" || jwter.SigningMethod == "ES384" || jwter.SigningMethod == "ES512" {
        if keyData, e := ioutil.ReadFile(jwter.PrivateKey); e == nil {
            secret, err = jwt.ParseECPrivateKeyFromPEM(keyData)
            
            if err != nil {
                token = ""
                return 
            }
        } else {
            token = ""
            err = errors.New("PrivateKey not exists")
            return 
        }
    }
    
    token, err = jwtToken.SignedString(secret)
    return
}

// 解析 token
func (jwter *JWT) ParseToken(strToken string) (jwt.MapClaims, error) {
    var claims jwt.MapClaims
    var err error
    var secret interface{}
    
    if jwter.SigningMethod == "RS256" || jwter.SigningMethod == "RS384" || jwter.SigningMethod == "RS512" {
        if keyData, e := ioutil.ReadFile(jwter.PublicKey); e == nil {
            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
            
            if err != nil {
                return claims, err
            }
        } else {
            err = errors.New("PublicKey not exists")
            return claims, err
        }
    } else if jwter.SigningMethod == "PS256" || jwter.SigningMethod == "PS384" || jwter.SigningMethod == "PS512" {
        if keyData, e := ioutil.ReadFile(jwter.PublicKey); e == nil {
            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
            
            if err != nil {
                return claims, err
            }
        } else {
            err = errors.New("PublicKey not exists")
            return claims, err
        }
    } else if jwter.SigningMethod == "HS256" || jwter.SigningMethod == "HS384" || jwter.SigningMethod == "HS512" {
        if secretData, e := ioutil.ReadFile(jwter.Secret); e == nil {
            secret = secretData
        } else {
            secret = []byte(jwter.Secret)
        }
    } else if jwter.SigningMethod == "ES256" || jwter.SigningMethod == "ES384" || jwter.SigningMethod == "ES512" {
        if keyData, e := ioutil.ReadFile(jwter.PublicKey); e == nil {
            secret, err = jwt.ParseECPublicKeyFromPEM(keyData)
            
            if err != nil {
                return claims, err
            }
        } else {
            err = errors.New("PublicKey not exists")
            return claims, err
        }
    }
    
    token, err := jwt.Parse(strToken, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })
    if err != nil {
        return claims, err
    }
    
    if err := token.Claims.Valid(); err != nil {
        return claims, err
    }
    
    var ok bool
    claims, ok = token.Claims.(jwt.MapClaims)
    if !ok {
        return claims, errors.New("Token claims get error")
    }

    return claims, nil
}

// 验证token是否有效
func (jwter *JWT) Verify(strToken string) error {
    _, err := jwter.ParseToken(strToken)
    
    if err != nil {
        return err
    }
    
    return nil
}
