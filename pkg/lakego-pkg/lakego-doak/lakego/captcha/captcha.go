package captcha

import (
    "github.com/mojocn/base64Captcha"
)

/**
 * 驱动接口
 *
 * @create 2021-10-19
 * @author deatil
 */
type IDriver interface {
    // 画图
    DrawCaptcha(content string) (item base64Captcha.Item, err error)

    // 生成验证码
    GenerateIdQuestionAnswer() (id, q, a string)
}

/**
 * 存储接口
 *
 * @create 2021-10-18
 * @author deatil
 */
type IStore interface {
    // 设置
    Set(string, string) error

    // 获取
    Get(string, bool) string

    // 验证
    Verify(string, string, bool) bool
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

// 验证码
func New(driver IDriver, store IStore) *Captcha {
    return &Captcha{
        Captcha: base64Captcha.NewCaptcha(driver, store),
    }
}

// 生成验证码
func (this *Captcha) Make() (string, string, error) {
    return this.Generate()
}

