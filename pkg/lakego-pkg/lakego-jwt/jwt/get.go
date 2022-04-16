package jwt

import (
    "errors"
)

// 从 token 获取解析后的[载荷]数据
func (this *JWT) GetClaimsFromToken(token *Token) (MapClaims, error) {
    claims, ok := token.Claims.(MapClaims)
    if !ok {
        return nil, errors.New("Token 载荷获取失败")
    }

    return claims, nil
}

// 从 token 获取解析后的[Header]数据
func (this *JWT) GetHeadersFromToken(token *Token) (ParsedHeaderMap, error) {
    headers := token.Header
    if len(headers) == 0 {
        return nil, errors.New("Token 的 Header 获取失败")
    }

    return headers, nil
}
