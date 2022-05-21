## 用户信息


> 我的信息
~~~
GET: /admin-api/profile
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
}
Response: {
    "id",
    "name",
    "nickname",
    "email",
    "avatar",
    "introduce",
    "last_active",
    "last_ip",
    "groups": []
    "is_sa",
}
~~~

> 信息更新
~~~
PUT: /admin-api/profile
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
    'nickname',
    'email',
    'introduce', // 简介
}
Response: {
}
~~~

> 更新头像
~~~
PATCH: /admin-api/profile/avatar
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
    'avatar',
}
Response: {
}
~~~

> 修改密码
~~~
PATCH: /admin-api/profile/password
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
    'oldpassword', // 密码均 md5 加密后
    'newpassword',
    'newpassword_confirm',
}
Response: {
}
~~~

> 权限列表
~~~
GET: /admin-api/profile/rules
Header: {
    'Authorization:Bearer ${accessToken}'
}
Request: {
}
Response: [
    'list', // 数组列表
]
~~~

