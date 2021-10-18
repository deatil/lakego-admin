package captcha

import (
    "image/color"

    "github.com/mojocn/base64Captcha"

    "github.com/deatil/lakego-admin/lakego/captcha/interfaces"
)

// id, b64s, err := New.Generate()
func New(config Config, store interfaces.Store) Captcha {
    /*
    //go:embed fonts/*.ttf
    //go:embed fonts/*.ttc
    var embeddedFontsFS embed.FS

    // 验证码字体驱动,
    var fontsStorage *base64Captcha.EmbeddedFontsStorage = base64Captcha.NewEmbeddedFontsStorage(embeddedFontsFS)
    */

    ds := base64Captcha.NewDriverString(
        config.Height,
        config.Width,
        config.NoiseCount,
        config.ShowLineOptions,
        config.Length,
        config.Source,
        &color.RGBA{
            R: config.RBGA.R,
            G: config.RBGA.G,
            B: config.RBGA.B,
            A: config.RBGA.A,
        },
        // 自定义字体目录，参考 fontsStorage 相关注释
        nil,
        []string{
            config.Fonts,
        },
    )

    driver := ds.ConvertFonts()

    return Captcha{
        Captcha: base64Captcha.NewCaptcha(driver, store),
    }
}

// 颜色
type RBGA struct {
    R uint8
    B uint8
    G uint8
    A uint8
}

// 配置
type Config struct {
    Height int
    Width int
    NoiseCount int
    ShowLineOptions int
    Length int
    Source string
    Fonts string

    RBGA RBGA
}

/**
 * 验证码
 *
 * @create 2021-9-15
 * @author deatil
 */
type Captcha struct {
    *base64Captcha.Captcha
}

// 生成验证码
func (captcha *Captcha) Make() (string, string, error) {
    return captcha.Generate()
}

