# UESTC_srun_login
UESTC的校园网登陆器

tags：电子科技大学 校园网登陆 多平台 深澜认证

## 介绍

学校的网线和wifi都需要登陆，需要打开网页。虽然现在有mac记录直接就能使用(手机wifi)，但是工位上的网线连接还是每次连接都要登陆

这个东西就是一个逆向“登陆js”的登陆器，用途是加到crontab让他自己连，以及一些边缘设备例如树莓派没有浏览器的登陆操作

电子科大使用的是SRunCGIAuthIntfSvr V1.18 B20181212

## 相关工作

已经有哥们有其他大学的同版本的pytohn脚本，可惜没有早点看到。

## 使用方法

下载源码，调整源码里面的配置，自己编译，然后丢到/usr/local/bin或者其他什么地方都行

`g++ -o srun_login srun_login.cpp -lcurl -lssl -lcrypto`

如果想使用配置文件的话，在程序的同目录写一个srun_login.conf配置文件

更推荐的方法是直接修改源码，把用户名，密码之类的全部硬编码，这样就不需要配置文件

srun_login -h 可以查看命令使用方式

## 配置文件

```conf
# srun_login 配置文件
# 使用格式: key=value
# 注释行以 # 或 ; 开头
# 行处理，等号分割，不需要操心特殊字符的处理
# 运行时的输入参数会覆盖配置文件中的相应项

# 服务器配置
server_host=10.253.0.237

# 用户配置
username_suffix=@dx-uestc
default_username=20245000000
default_password=0000000000

# 网络配置
default_ip=0.0.0.0
default_interface=enp2s0

# HTTP配置
user_agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36

# 协议配置
fake_callback_prefix=jQuery1124011346170079978446_
acid=1
enc_ver=srun_bx1
n=200
type=1
os=Linux
name=Linux
double_stack=0
```

配置解释：
server_host：登陆页面的IP地址
default_username：学号
default_password：密码
username_suffix：学校的用户名后缀（学校不同可能就不同，可以在浏览器F12看网络里面的GET请求，最后跟学号组装到一起。例如成电的是20240000000@dx-uestc）
default_interface：获取IP地址的网卡，至少在UESTC你可以不管，反正验证阶段使用的是服务器返回的client_ip
后面其他的配置就需要自己去F12看请求参数了，不同学校可能不一样

例如UESTC的请求是：
```
GET /cgi-bin/srun_portal?callback=jQuery1124011346170079978446_1756439978000&action=login&username=20240000000@dx-uestc&password={MD5}195e94eb356a34xxxxxxe1c283dbf9b&ac_id=1&ip=218.194.55.165&chksum=0b52f930df233472b4ebc4cfd3790f1738a23898&info={SRBX1}w1mQQ+/2fG5Fb1A4TkRsmpXR2no7BHR+KImuVos2pjr1wCQlGI2h2wf6Sw8cR7sDg3JT35S7aJSxNvInkkOqrvQDMu+ue4Vdd3773SFFNIthzowDFWaCtuZvX9BZ2+YsnxKr6BzRK6CgB1Ep1tllpnIZPA64puNj&n=200&type=1&os=Linux&name=Linux&double_stack=0&_=1756439978000 HTTP/1.1 
```

## 工作原理

这个倒是挺简单的

1. 本机向登陆服务器发送验证请求get_challenge()
2. 服务器返回一个jsonp,里面有关键参数challenge和client_ip,也就是验证码和客户端IP
3. 逆向js文件，构造最终的get请求。发送
4. 好了。。

坑点：里面用的md5是hmac-md5,然后base64也是用的diy过的。这两个函数都需要重新移植
最大的坑就是他的验证手段，使用的一堆位运算加密(xEncode()函数)，命名SRBX1加密
然后请求构造好了需要urlencode。（大坑，debug了好久）
