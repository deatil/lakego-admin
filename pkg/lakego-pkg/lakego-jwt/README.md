## JWT


### 项目介绍

*  JWT 生成和验证


### 下载安装

~~~go
go get -u github.com/deatil/lakego-jwt
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/lakego-jwt/jwt"
)

func main() {
    jwter := jwt.New().
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
        WithPrivateKeyPassword(privateKeyPassword).
        WithClaim(k, v)

    token := jwter.MakeToken()
    fmt.Println("生成的 Token 为：", token)

    // 解析 token
    parsedToken, err := jwter.WithJti(jti).ParseToken(token)

    // 验证数据
    ok, err := jwter.Validate(parsedToken)

    // 验证是否过期相关
    ok, err := jwter.Verify(parsedToken)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
