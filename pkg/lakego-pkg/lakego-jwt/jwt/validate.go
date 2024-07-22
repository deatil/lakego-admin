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

    aud, ok := this.Claims["aud"].(string)
    if !ok || claims.VerifyAudience(aud, false) == false {
        return false, errors.New("Audience Verify fail")
    }

    iss, ok := this.Claims["iss"].(string)
    if !ok || claims.VerifyIssuer(iss, false) == false {
        return false, errors.New("Issuer Verify fail")
    }

    return true, nil
}
