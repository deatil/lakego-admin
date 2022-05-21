## 系统api接口文档

*  系统 api 提交的数据通常 `POST`、 `PUT` 及 `PATCH` 以 `JSON` 格式提交，其他均以 `URL` 参数提交
*  部分响应code码可查看 `github.com/deatil/lakego-doak-admin/admin/support/http/code` 文件


### 接口请求

请求 Body 格式为 `JSON`

> 请求头信息

需要鉴权的需要加上以下请求头信息

```php
Header: {
    'Authorization:Bearer ${accessToken}'
}
```


### 接口响应

> 响应通用格式，返回格式为 `JSON`

```json
{
    "success": true,
    "code": 200,
    "message": "success",
    "data": {
        ...
    }
}
```

`success` 字段有 `true` 和 `false` 两个结果

`code` 字段为结果响应码，通常为0时返回正确结果

`message` 字段为结果提示

`data` 字段通常为输出结果，接口文档内的 `Response` 内容为该字段内容

