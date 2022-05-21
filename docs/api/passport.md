## 用户登陆


> 验证码
~~~
GET: /admin-api/passport/captcha
Response-Header: {
    'Lakego-Admin-Captcha-Id'
}
Response: {
    'captcha',
}
~~~

> 登陆
~~~
POST: /admin-api/passport/login
Request-Header: {
    'Lakego-Admin-Captcha-Id'
}
Request: {
    'name': name,
    'password': md5(password),
    'captcha': captcha,
}
Response: {
    'access_token', // 鉴权Token
    'expires_in', // access_token过期时间
    'refresh_token', // 刷新Token
}
~~~

> 刷新Token
~~~
PUT: /admin-api/passport/refresh-token
Request: {
    'refresh_token',
}
Response: {
    'access_token', // 鉴权Token
    'expires_in', // access_token过期时间
}
~~~

> 退出
~~~
DELETE: /admin-api/passport/logout
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
    'refresh_token', // 刷新Token
}
Response: {
}
~~~

