package captcha

import (
    "github.com/mojocn/base64Captcha"

    "github.com/deatil/lakego-admin/lakego/captcha/interfaces"
)

// 验证码
func New(driver interfaces.Driver, store interfaces.Store) Captcha {
    return Captcha{
        Captcha: base64Captcha.NewCaptcha(driver, store),
    }
}

/**
 * 验证码
 *
 * id, b64s, err := New().Make()
 *
 * @create 2021-9-15
 * @author deatil
 */
type Captcha struct {
    *base64Captcha.Captcha
}

// 生成验证码
func (this *Captcha) Make() (string, string, error) {
    return this.Generate()
}

