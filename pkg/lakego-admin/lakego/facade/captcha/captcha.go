package captcha

import (
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/captcha"
    "github.com/deatil/lakego-admin/lakego/facade/redis"
)

/**
 * 验证码
 *
 * @create 2021-6-20
 * @author deatil
 */
func New() captcha.Captcha {
    conf := config.New("captcha")

    key := conf.GetString("Key")
    expireTimes := conf.GetInt("ExpireTimes")
    height := conf.GetInt("Height")
    width := conf.GetInt("Width")
    noiseCount := conf.GetInt("NoiseCount")
    showLineOptions := conf.GetInt("ShowLineOptions")
    length := conf.GetInt("Length")
    source := conf.GetString("Source")
    fonts := conf.GetString("Fonts")

    rgbaR := conf.GetInt("RGBA.R")
    rgbaG := conf.GetInt("RGBA.G")
    rgbaB := conf.GetInt("RGBA.B")
    rgbaA := conf.GetInt("RGBA.A")

    return captcha.New(captcha.Config{
        Key: key,
        ExpireTimes: expireTimes,
        Height: height,
        Width: width,
        NoiseCount: noiseCount,
        ShowLineOptions: showLineOptions,
        Length: length,
        Source: source,
        Fonts: fonts,

        RBGA: captcha.RBGA{
            R: uint8(rgbaR),
            G: uint8(rgbaG),
            B: uint8(rgbaB),
            A: uint8(rgbaA),
        },
    }, redis.New())
}

