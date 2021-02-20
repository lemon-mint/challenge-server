```
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name  example.com;
    location / {
        auth_request /verify;
        proxy_pass http://some.backend.server.example.com;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /_v_challenge {
        proxy_pass http://127.0.0.1:59710;
        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
    
    location = /verify {
        proxy_pass http://127.0.0.1:59710/verify/cookie;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
    
    error_page   401 402 403 404  /auth;
    location = /auth {
        proxy_pass http://127.0.0.1:59710/challenge;
        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
    
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
```
