package captcha

import (
    "image/color"
    "time"

    "github.com/mojocn/base64Captcha"
    
    "lakego-admin/lakego/redis"
)

type Config struct {
    Key string
    ExpireTimes int
    
    Height int
    Width int
    NoiseCount int
    ShowLineOptions int
    Length int
    Source string
    Fonts string
}

type Captcha struct {
    *base64Captcha.Captcha
}

type CaptchaStore struct {
    key    string
    redis  *redis.Redis
    config Config
}

// id, b64s, err := New.Generate()
func New(config Config, redis redis.Redis) Captcha {
    ds := base64Captcha.NewDriverString(
        config.Height, // 46,
        config.Width, // 140,
        config.NoiseCount, // 2,
        config.ShowLineOptions, // 2,
        config.Length, // 4,
        config.Source, // "234567890abcdefghjkmnpqrstuvwxyz",
        &color.RGBA{R: 240, G: 240, B: 246, A: 246},
        []string{config.Fonts}, // []string{"wqy-microhei.ttc"},
    )

    driver := ds.ConvertFonts()
    store := CaptchaStore{
        redis:  &redis,
        key:    config.Key,
        config:	config,
    }

    return Captcha{
        Captcha: base64Captcha.NewCaptcha(driver, store),
    }
}

func (a CaptchaStore) getKey(v string) string {
    return a.key + ":" + v
}

func (a CaptchaStore) Set(id string, value string) {
    t := time.Second * time.Duration(a.config.ExpireTimes)
    a.redis.Set(a.getKey(id), value, int(t))
}

func (a CaptchaStore) Get(id string, clear bool) string {
    var (
        key = a.getKey(id)
        val string
    )

    err := a.redis.Get(key, &val)
    if err != nil {
        return ""
    }

    if !clear {
        a.redis.Delete(key)
    }

    return val
}

func (a CaptchaStore) Verify(id, answer string, clear bool) bool {
    v := a.Get(id, clear)
    return v == answer
}
