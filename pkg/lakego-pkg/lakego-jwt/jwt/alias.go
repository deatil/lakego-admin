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

// New(method SigningMethod) *Token
var NewJWT = jwt.New

// NewWithClaims(method SigningMethod, claims Claims) *Token
var NewWithClaims = jwt.NewWithClaims

// Parse(tokenString string, keyFunc Keyfunc, options ...ParserOption) (*Token, error)
var Parse = jwt.Parse

// ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, options ...ParserOption) (*Token, error)
var ParseWithClaims = jwt.ParseWithClaims

// EncodeSegment(seg []byte) string
var EncodeSegment = jwt.EncodeSegment

// DecodeSegment(seg string) ([]byte, error)
var DecodeSegment = jwt.DecodeSegment
