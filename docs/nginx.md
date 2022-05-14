## Nginx 同域名部署前后端分离项目

前后端分离项目，前后端共用一个域名。通过域名后的 url 前缀来区别前后端项目。


~~~conf
# yourdomain.conf

# 代理配置
upstream admin {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name yourdomain.com; # 配置项目域名
    index index.html index.htm;

    # 默认访问前端项目
    location / {
        # 前端打包后的静态目录
        alias /path/dist/;
        #解决页面刷新404问题
        try_files $uri $uri/ /index.html;
    }

    # 后端项目
    location ~* ^/(admin-api) {
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 5m;
        proxy_pass http://admin;
    }
    #PHP-INFO-END

    # 前端静态资源处理
    location  ^~ /images/ {
        alias /path/dist/images/;
    }

    # 后端静态资源处理
    location  ^~ /vendor/ {
        alias /path/public/vendor/;
    }
    location  ^~ /storage/ {
        alias /path/public/storage/;
    }
}
~~~

~~~conf
upstream dfs_stream {
    server host1:port;
    server host2:port;
    ip_hash;
}

ocation ~ /dfs1/group([0-9]) {
    access_log logs/dfs/access.log main;
    error_log logs/dfs/error.log error;
    rewrite ^/dfs1/(.*)$ /$1 break;
    proxy_pass http://localhost:8051;
    # Disable request and response buffering
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Host $host:$server_port;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # 如果server_name不是公网域名，这个地方可以设置成ip
    proxy_set_header X-Forwarded-Host $hostname;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    # 因为使用了前缀加rewrite，所以要修改返回的Location加上反向代理的前缀
    proxy_redirect ~^(.*)/group([0-9])/big/upload/(.*) /dfs/group$2/big/upload/$3;
    client_max_body_size 0;
}
~~~
