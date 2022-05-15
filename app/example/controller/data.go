package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/go-pipeline/pipeline"
    "github.com/deatil/go-exception/exception"
    "github.com/deatil/go-cryptobin/cryptobin"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/str"
    "github.com/deatil/lakego-doak/lakego/math"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/snowflake"
    "github.com/deatil/lakego-doak/lakego/facade/sign"
    // "github.com/deatil/lakego-doak/lakego/facade/cache"
    // "github.com/deatil/lakego-doak/lakego/facade/redis"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 数据
 *
 * @create 2022-1-9
 * @author deatil
 */
type Data struct {
    controller.Base
}

/**
 * 信息
 */
func (this *Data) Index(ctx *gin.Context) {
    this.Fetch(ctx, "example::index", gin.H{
        "msg": "测试数据",
    })
}

/**
 * 信息2
 */
func (this *Data) Show(ctx *gin.Context) {
    this.Fetch(ctx, "example::show.index", map[string]any{
        "msg": "测试数据",
    })
}

/**
 * Error 测试
 */
func (this *Data) Error(ctx *gin.Context) {
    // 报错测试
    data := []string{}
    exception.
        Try(func(){
            panic("exception error test")

            // exception.Throw("exception error test 222")
        }).
        Catch(func(e exception.Exception){
            // data = e.GetMessage()

            trace := e.GetTrace()
            for _, ev := range trace {
                data = append(data, ev.LongString())
            }
        })

    // 管道测试
    data2 := pipeline.NewPipeline().
        WithCarryCallback(func(carry any) any {
            return carry
        }).
        Send("开始的数据").
        Through(
            func(data any, next pipeline.NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                data2 := next(old)
                data2 = data2.(string) + ", 第1次数据2"

                return data2
            },
            func(data any, next pipeline.NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                data2 := next(old)
                data2 = data2.(string) + ", 第2次数据2"

                return data2
            },
            // 不符时跳过
            func(data any, next pipeline.NextFunc) {
            },
            PipelineEx{},
        ).
        ThenReturn()

    // hub 测试
    hub := pipeline.NewHub()
    hub.Pipeline("hub", func(pipe *pipeline.Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next pipeline.NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    data2 := next(old)
                    data2 = data2.(string) + ", 第1次数据2"

                    return data2
                },
            ).
            ThenReturn()

        return data
    })
    data3 := hub.Pipe("hub 测试", "hub")

    // 雪花算法
    snowflakeId, _ := snowflake.Make(5)

    // 文件管理
    fs := filesystem.New()
    img := "./runtime/test/13123/123321.txt"
    fsInfo := fs.IsWritable(img)

    // 字符处理
    strData := "t_ydfd_ydf"
    newStrData := str.LowerCamel(strData)

    // 时间
    date := datebin.
        Now().
        AddDay().
        ToDatetimeString()
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString()

    // SM4 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12").
        Des().
        ECB().
        ISO10126Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("bvifBivJ1GEXAEgBAo9OoA==").
        SetKey("dfertf12").
        Des().
        ECB().
        ISO10126Padding().
        Decrypt().
        ToString()

    // 生成证书
    rsa := cryptobin.NewRsa()
    rsaPriKey := rsa.
        GenerateKey(2048).
        CreatePKCS8WithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    rsaPubKey := rsa.
        FromPKCS8WithPassword([]byte(rsaPriKey), "123").
        CreatePublicKey().
        ToKeyString()

    // 签名
    hashData := hash.FromString("123").MD5().ToString()

    // 编码
    encodeStr := encoding.FromString("test-data").ToBase64String()
    encodeStr2 := encoding.FromBase64String("dGVzdC1kYXRh").ToString()
    encodeStr3 := encoding.FromConvertHex("573d").ToConvertDecString()

    // 签名
    signData := sign.Sign("md5").
        WithData("test", "测试测试").
        WithAppID("API123456").
        GetSignMap()

    // 数组相关
    mathData := math.Decbin(123)
    mathData2 := math.Bindec("1111011")

    // 数组
    arrData := map[string]any{
        "a": 123,
        "b": map[string]any{
            "c": "ccc",
            "d": map[string]any{
                "e": "eee",
                "f": map[string]any{
                    "g": "ggg",
                },
            },
            "dd": []any{
                "ccccc",
                "ddddd",
                "fffff",
            },
            "ff": map[any]any{
                111: "fccccc",
                222: "fddddd",
                333: "dfffff",
            },
        },
    }
    arr := array.ArrGet(arrData, "b.d.e")

    // 缓存
    // cache.New().Forever("lakego-cache-forever", "lakego-cache-Forever-data")
    // cacheData, _ := cache.New().Get("lakego-cache-forever")

    // redis
    // redis.New().Set("go-redis", "go-redis-data", 60000)
    // var redisData string
    // redis.New().Get("go-redis", &redisData)

    this.SuccessWithData(ctx, "Error 测试", gin.H{
        // "cacheData": cacheData,
        // "redisData": redisData,

        "error": data,
        "data2": data2,
        "data3": data3,
        "snowflakeId": snowflakeId,

        "img": img,
        "fsInfo": fsInfo,

        "str": newStrData,

        "date": date,
        "date2": date2,

        "cypt": cypt,
        "cyptde": cyptde,

        "rsaPriKey": rsaPriKey,
        "rsaPubKey": rsaPubKey,

        "hashData": hashData,

        "encodeStr": encodeStr,
        "encodeStr2": encodeStr2,
        "encodeStr3": encodeStr3,

        "signData": signData,

        "mathData": mathData,
        "mathData2": mathData2,

        "arr": arr,
    })
}

/* ======================== */

// 管道测试
type PipelineEx struct {}

func (this PipelineEx) Handle(data any, next pipeline.NextFunc) any {
    old := data.(string)

    old = old + ", struct 数据开始"

    data2 := next(old)

    data2 = data2.(string) + ", struct 数据结束"

    return data2
}
