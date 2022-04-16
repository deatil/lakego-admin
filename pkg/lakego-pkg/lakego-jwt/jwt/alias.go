package jwt

import (
    "github.com/golang-jwt/jwt/v4"
)

// jwt 别名
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
