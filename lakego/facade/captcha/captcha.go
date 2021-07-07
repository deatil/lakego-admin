package captcha

import (
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/captcha"
	"lakego-admin/lakego/facade/redis"
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
	}, redis.New())
}

