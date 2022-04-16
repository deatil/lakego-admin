package jwt

import (
    "errors"
)

// token 过期检测
func (this *JWT) Validate(token *Token) (bool, error) {
    if err := token.Claims.Valid(); err != nil {
        return false, err
    }

    return true, nil
}

// 验证 token 是否有效
func (this *JWT) Verify(token *Token) (bool, error) {
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
