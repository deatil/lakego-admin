package controller

import (
    "encoding/hex"
    "github.com/gin-gonic/gin"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-crc/crc"
    "github.com/deatil/go-crc/crc12"
    "github.com/deatil/go-crc8/crc8"
    "github.com/deatil/go-crc16/crc16"
    "github.com/deatil/go-crc32/crc32"
    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/go-pipeline/pipeline"
    "github.com/deatil/go-exception/exception"
    "github.com/deatil/lakego-filesystem/filesystem"

    _ "github.com/deatil/go-cryptobin/cryptobin/ca"
    _ "github.com/deatil/go-cryptobin/cryptobin/dsa"
    _ "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    _ "github.com/deatil/go-cryptobin/cryptobin/eddsa"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
    cryptobin_crypto "github.com/deatil/go-cryptobin/cryptobin/crypto"

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
        ).
        Through(
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
    hub.Pipeline("hub", func(pipe pipeline.Pipeline, object any) any {
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
        Format("r")
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString()

    // SM4 加密测试
    cypt := cryptobin_crypto.
        FromString("test-pass").
        SetKey("dfertf12").
        Des().
        ECB().
        ISO10126Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin_crypto.
        FromBase64String("bvifBivJ1GEXAEgBAo9OoA==").
        SetKey("dfertf12").
        Des().
        ECB().
        ISO10126Padding().
        Decrypt().
        ToString()

    // 生成证书
    rsa := cryptobin_rsa.NewRsa()
    rsaPriKey := rsa.
        GenerateKey(2048).
        CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    rsaPubKey := rsa.
        FromPKCS8PrivateKeyWithPassword([]byte(rsaPriKey), "123").
        CreatePublicKey().
        ToKeyString()

    // 签名
    hashData := hash.FromString("123").MD5().ToString()
    hashData2 := hash.Murmur32("测试测试")

    // 编码
    encodeStr := encoding.FromString("test-data").ToBase64String()
    encodeStr2 := encoding.FromBase64String("dGVzdC1kYXRh").ToString()
    encodeStr3 := encoding.FromConvertHex("573d").ToConvertDecString()

    // encodeStr3 = encoding.FromString("测试测试12121").ToBase62String()
    // encodeStr3 = encoding.FromBase62String("SzXXlHtJaq9gTV93SeM8v6v").ToString()

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

    // sm2 签名
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes := encoding.FromBase64String(sm2key).ToBytes()
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]
    sm2Sign := cryptobin_sm2.NewSM2().
        FromPrivateKeyBytes(sm2keyBytes).
        FromString(sm2data).
        SignHex([]byte(sm2userid)).
        ToBase64String()

    // crc8
    crc8Hex, _ := hex.DecodeString("010f00")
    crc8Data := crc8.ChecksumROHC(crc8Hex)
    crc8Data2 := crc8.ToHexString(crc8Data)

    crc8Hash := crc8.NewCRC8Hash(crc8.CRC8_ROHC)
    crc8Hash.Write(crc8Hex)
    crc8HashData := crc8Hash.Sum(nil)
    crc8HashData2 := hex.EncodeToString(crc8HashData)

    // crc16
    // 16进制字符转为 byte
    crc16Hex, _ := hex.DecodeString("010f00")
    // encodedStr := hex.EncodeToString(b)
    crc16Data := crc16.ChecksumXMODEM2(crc16Hex)
    crc16Data2 := crc16.ToHexString(crc16Data)

    crc16Hash := crc16.NewCRC16Hash(crc16.CRC16_XMODEM2)
    crc16Hash.Write(crc16Hex)
    crc16HashData := crc16Hash.Sum(nil)
    crc16HashData2 := hex.EncodeToString(crc16HashData)

    // crc32
    crc32Hex, _ := hex.DecodeString("020fa156739865e221")
    crc32Data := crc32.ChecksumKoopman(crc32Hex)
    crc32Data2 := crc32.ToHexString(crc32Data)

    crc32Hash := crc32.NewCRC32Hash(crc32.CRC32_Koopman)
    crc32Hash.Write(crc32Hex)
    crc32HashData := crc32Hash.Sum(nil)
    crc32HashData2 := hex.EncodeToString(crc32HashData)

    // crc
    crcHex, _ := hex.DecodeString("0208")
    crcData := crc.Crc6Itu(crcHex)
    crcData2 := crc.ToHexString(crcData, "crc6")

    // hashCrc32Data
    hashCrc32Data := hash.CRC32Koopman(string(crc32Hex))

    // crc12
    crc12Hex, _ := hex.DecodeString("31303432")
    crc12Data := crc12.ChecksumCRC12(crc12Hex)
    crc12Data2 := crc12.ToHexString(crc12Data) // 3CD

    crc12Hash := crc12.NewCRC12Hash(crc12.CRC12)
    crc12Hash.Write(crc12Hex)
    crc12HashData := crc12Hash.Sum(nil)
    crc12HashData2 := crc12.ToHexStringFromBytes(crc12HashData)

    // 验证
    obj2 := cryptobin_rsa.New()

    obj2Pri, _ := fs.Get("./runtime/key/rsa_pkcs8_en55")
    obj2cypt := obj2.
        FromString("test-pass").
        FromPKCS8PrivateKeyWithPassword([]byte(obj2Pri), "123").
        Sign().
        ToBase64String()
    obj2Pub, _ := fs.Get("./runtime/key/rsa_pkcs8_en55.pub")
    obj2cyptde := obj2.
        FromBase64String("qlhbWcgPwvspaE4qiDTk8EVNUq/DKnvkwFDtejRLk6pbktXHQwuEDrglvB5WB9OJEAueg5ZU4Pyx9E5vpoCGYKVhT9Q3LjlHl9klcXQZLuXn+7rF/5tLLyZhveyCMPiZxjLCP9nYZvJVLhZ9kpn6Iye//h8NODl3v8EN4H5S64lPEtryFjfRSm5r4b80/WiDqrVNZDKyRpdNg6Rp66oK3TOMe5OUX0oxq1DVEEvd5G1IqXjMwEsBvLmnuA7V3EBN1Uq/SjNZR7P0S8/ArT6LytwwBQ5vURXVYE0Km9qJeGok4a2pna3eNROLVfzOyeO6kap8i8Hb0rJ9xOZK+57dNA==").
        FromPublicKey([]byte(obj2Pub)).
        Very([]byte("test-pass")).
        ToVeryed()

    this.SuccessWithData(ctx, "Error 测试", gin.H{
        "obj2cypt": obj2cypt,
        "obj2cyptde": obj2cyptde,

        "crcData": crcData2,

        "crc12Data": crc12Data2,
        "crc12HashData": crc12HashData2,

        "crc8Data": crc8Data2,
        "crc8HashData": crc8HashData2,

        "crc16Data": crc16Data2,
        "crc16HashData": crc16HashData2,

        "crc32Data": crc32Data2,
        "crc32HashData": crc32HashData2,

        "hashCrc32Data": hashCrc32Data,

        // "cacheData": cacheData,
        // "redisData": redisData,

        "sm2Sign": sm2Sign,

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
        "hashData2": hashData2,

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
