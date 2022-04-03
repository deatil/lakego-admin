package interfaces

import (
    "github.com/mojocn/base64Captcha"
)

/**
 * 驱动接口
 *
 * @create 2021-10-19
 * @author deatil
 */
type Driver interface {
    // 画图
    DrawCaptcha(content string) (item base64Captcha.Item, err error)

    // 生成验证码
    GenerateIdQuestionAnswer() (id, q, a string)
}
