---
layout: post
title:  渗透测试岗位面试题多人实战大汇总
tags: 渗透 渗透测试
categories: 渗透
published: true
---



## 常见面试题总结

## 1、假如给你一个网站你怎么去渗透？

```text
信息收集

首先看是什么类型的网站，针对不同类型的网站有不同的信息搜集方案，如大型企业网站可以用天眼查，启信宝等查询法人股份等信息，小型网站可以查询使用了哪类建站系统

	1，whois查詢,获取注册者邮箱姓名电话等。

	2，查询服务器旁站以及子域名站点，因为主站一般比较难，所以先看看旁站有没有通用性的cms或者其他漏洞。

	3，查看服务器操作系统版本，web中间件，看看是否存在已知的漏洞，比如IIS，APACHE,NGINX的解析漏洞

	4，查看IP，进行IP地址端口扫描，对响应的端口进行漏洞探测，比如 rsync,心脏出血，mysql,ftp,ssh弱口令等。

	5，扫描网站目录结构，看看是否可以遍历目录，或者敏感文件泄漏，比如php探针

	6，google hack 进一步探测网站的信息，后台，敏感文件

	7，查看这个网站都有哪些功能，针对不同的功能可以实现不同的漏洞利用
```

## 2、whois查詢主要查的是什么?

```text
1.域名信息

2.注册商

3.联系人

4.联系邮箱

5.网站创建时间

6.网站过期时间

7.DNS信息

8.网站状态

	拓展：什么是whois？

		whois可以理解为域名数据库搜索弓|擎
```

## 3、常用哪些查询网站

```text
1.中国互联网信息中心whois查询

官网地址：http://www.cnnic.net.cn/

2.站长之家whois查询

官网地址：http://whois.chinaz.com/

3.站长工具whois查询

官网地址：http://tool.chinaz.com/ipwhois/

4.全球whois查询

官网地址：https://www.whois365.com/cn/

5.全球whois查询

官网地址：https://www.whois365.com/cn/

6.百度云whois查询

官网地址：https://cloud.baidu.com/product/bcd.html?track=cp:aladdin%7Ckw:148

7.新网whois查询

官网地址：http://whois.xinnet.com/domain/whois_login.jsp

8.时代互联

网址地址：http://www.now.cn/

9.alexa.cn whois查询

官网地址：http://whois.alexa.cn/

10.whoissoft.com

官网地址：http://whoissoft.com/

11.爱名网whois查询

官网地址：https://whois.22.cn/

12.网络工具大全

官网地址：http://tools.now.cn/

13.网站建设

官网地址：http://www.zw.cn/

14.中国万网whois

官网地址：http://whois.zw.cn/
```

## 4、给你个域名怎么知道ip地址？

```text
1.最简单的用ping

2.nslookup+域名查看

3.利用站长之家等在线查询网站

4.云悉等指纹识别

5.ToolBox等浏览器插件
```

## 5、nmap扫描端口用什么命令?

```text
-p 加端口号或1-65535

	拓展：nmap端口扫描参数

		-sS (TCP SYN扫描)

		-sT (TCP connect()扫描)

		-sU (UDP扫描)

		-sV (版本探测)

		-O (启用操作系统检测)

		-f (报文分段); --mtu (使用指定的MTU)

		-D <decoy1 ，decoy2，...> (使用诱饵隐蔽扫描)

		-S <IP_Address> (源地址哄骗)
```

## 6、网站常见容器有哪些？

```text
WebLogic

WebSphere

JBoss

Tomcat

IIS

Apache

Nginx
```

## 7、IIS常见漏洞

```text
1、PUT漏洞

2、短文件名猜解

3、远程代码执行

4、解析漏洞
```

## 8、发现IIS的网站，怎样试它的漏洞？

```text
区分版本

	1.IIS6.0/7.5解析漏洞

	2.IIS 7.5 NET源代码泄露和身份验证漏洞

	3.IIS 7.5经典的ASP验证绕过

	4.IIS 6.0安装PHP绕过认证漏洞
```

## 9、遇到WebLogic的网站容器，你会测什么漏洞？

```text
weblogic反序列化漏洞
```

## 10、常测什么端口

```text
443 网页浏览端口

445 共享文件夹

3306 mysql数据库

1443 mssql数据库

20 21 ftp

	拓展：常见端口号

		端口号    端口说明    				攻击技巧

		21/22/69  ftp/tftp：文件传输协议    爆破\嗅探\溢出\后门

		22    	  ssh：远程连接    			爆破OpenSSH；28个退格

		23    	  telnet：远程连接    		爆破\嗅探

		25    	  smtp：邮件服务    		邮件伪造

		53   	  DNS：域名系统    			DNS区域传输\DNS劫持\DNS缓存投毒\DNS欺骗\利用DNS隧道技术刺透防火墙

		67/68     dhcp    					劫持\欺骗

		110    	  pop3    					爆破

		139    	  samba    					爆破\未授权访问\远程代码执行

		143    	  imap    					爆破

		161    	  snmp      				爆破

		389       ldap    					注入攻击\未授权访问

		512/513/514 linux r    				直接使用rlogin

		873    	  rsync    					未授权访问

		1080    socket    					爆破：进行内网渗透

		1352    lotus    					爆破：弱口令\信息泄漏：源代码

		1433    mssql    					爆破：使用系统用户登录\注入攻击

		1521    oracle    					爆破：TNS\注入攻击

		2049    nfs    						配置不当

		2181    zookeeper    				未授权访问

		3306    mysql    					爆破\拒绝服务\注入

		3389    rdp    						爆破\Shift后门

		4848    glassfish    				爆破：控制台弱口令\认证绕过

		5000    sybase/DB2    				爆破\注入

		5432    postgresql    				缓冲区溢出\注入攻击\爆破：弱口令

		5632    pcanywhere    				拒绝服务\代码执行

		5900    vnc    						爆破：弱口令\认证绕过

		6379    redis    					未授权访问\爆破：弱口令

		7001    weblogic    				Java反序列化\控制台弱口令\控制台部署webshell

		80/443/8080    web    				常见web攻击\控制台爆破\对应服务器版本漏洞

		8069    zabbix    					远程命令执行

		9090    websphere控制台    			爆破：控制台弱口令\Java反序列

		9200/9300 elasticsearch    			远程代码执行

		11211    memcacache    				未授权访问

		27017    mongodb    				爆破\未授权访问
```

## 11、内网扫描到445端口测什么漏洞？

```text
永恒之蓝ms17-010
```

## 12、内网如何实现跨域？

```text
1.jsonp跨域		

利用了 script 不受同源策略的限制

缺点：只能 get 方式，易受到 XSS攻击

2.CORS跨域		

当使用XMLHttpRequest发送请求时，如果浏览器发现违反了同源策略就会自动加上一个请求头 origin；

后端在接受到请求后确定响应后会在后端在接受到请求后确定响应后会在 Response Headers 中加入一个属性 Access-Control-Allow-Origin；

浏览器判断响应中的 Access-Control-Allow-Origin 值是否和当前的地址相同，匹配成功后才继续响应处理，否则报错

缺点：忽略 cookie，浏览器版本有一定要求

3.代理跨域请求

前端向发送请求，经过代理，请求需要的服务器资源

缺点：需要额外的代理服务器

4.Html5 postMessage 方法

允许来自不同源的脚本采用异步方式进行有限的通信，可以实现跨文本、多窗口、跨域消息传递

缺点：浏览器版本要求，部分浏览器要配置放开跨域限制

5.修改 document.domain 跨子域

相同主域名下的不同子域名资源，设置 document.domain 为 相同的一级域名

缺点：同一一级域名；相同协议；相同端口

6.基于 Html5 websocket 协议

websocket 是 Html5 一种新的协议，基于该协议可以做到浏览器与服务器全双工通信，允许跨域请求

缺点：浏览器一定版本要求，服务器需要支持 websocket 协议

7.document.xxx + iframe

通过 iframe 是浏览器非同源标签，加载内容中转，传到当前页面的属性中

缺点：页面的属性值有大小限制
```

## 13、用什么方法实现反向代理？

```text
EarthWorm

reGeorg-master

Tunna-master

proxifier
```

## 14、外网渗透会用到哪些工具？

```text
Metasploit

SQLmap

Nmap

BeEF

Social Engineer Toolkit(SET)

Wireshark

w3af

CORE Impact

OWASP ZAP

Canvas

Aircrack-ng

Burp Suite

Hydra

John the Ripper

AWVS

御剑
```

## 15、sqlmap盲注用什么参数？

```text
-technique

	拓展：sql注入工具sqlmap使用参数说明

		Options（选项）：

		--version 显示程序的版本号并退出

		-h, --help 显示此帮助消息并退出

		-v VERBOSE 详细级别：0-6（默认为1）

		Target（目标）：以下至少需要设置其中一个选项，设置目标URL。

		-d DIRECT 直接连接到数据库。

		-u URL, --url=URL 目标URL。

		-l LIST 从Burp或WebScarab代理的日志中解析目标。

		-r REQUESTFILE 从一个文件中载入HTTP请求。

		-g GOOGLEDORK 处理Google dork的结果作为目标URL。

		-c CONFIGFILE 从INI配置文件中加载选项。

		Request（请求）：:这些选项可以用来指定如何连接到目标URL。

		--data=DATA 通过POST发送的数据字符串

		--cookie=COOKIE HTTP Cookie头

		--cookie-urlencode URL 编码生成的cookie注入

		--drop-set-cookie 忽略响应的Set - Cookie头信息

		--user-agent=AGENT 指定 HTTP User - Agent头

		--random-agent 使用随机选定的HTTP User - Agent头

		--referer=REFERER 指定 HTTP Referer头

		--headers=HEADERS 换行分开，加入其他的HTTP头

		--auth-type=ATYPE HTTP身份验证类型（基本，摘要或NTLM）(Basic, Digest or NTLM)

		--auth-cred=ACRED HTTP身份验证凭据（用户名:密码）

		--auth-cert=ACERT HTTP认证证书（key_file，cert_file）

		--proxy=PROXY 使用HTTP代理连接到目标URL

		--proxy-cred=PCRED HTTP代理身份验证凭据（用户名：密码）

		--ignore-proxy 忽略系统默认的HTTP代理

		--delay=DELAY 在每个HTTP请求之间的延迟时间，单位为秒

		--timeout=TIMEOUT 等待连接超时的时间（默认为30秒）

		--retries=RETRIES 连接超时后重新连接的时间（默认3）

		--scope=SCOPE 从所提供的代理日志中过滤器目标的正则表达式

		--safe-url=SAFURL 在测试过程中经常访问的url地址

		--safe-freq=SAFREQ 两次访问之间测试请求，给出安全的URL

		Optimization（优化）：这些选项可用于优化SqlMap的性能。

		-o 开启所有优化开关

		--predict-output 预测常见的查询输出

		--keep-alive 使用持久的HTTP（S）连接

		--null-connection 从没有实际的HTTP响应体中检索页面长度

		--threads=THREADS 最大的HTTP（S）请求并发量（默认为1）

		Injection（注入）：这些选项可以用来指定测试哪些参数， 提供自定义的注入payloads和可选篡改脚本。

		-p TESTPARAMETER 可测试的参数（S）

		--dbms=DBMS 强制后端的DBMS为此值

		--os=OS 强制后端的DBMS操作系统为这个值

		--prefix=PREFIX 注入payload字符串前缀

		--suffix=SUFFIX 注入payload字符串后缀

		--tamper=TAMPER 使用给定的脚本（S）篡改注入数据

		Detection（检测）：

		这些选项可以用来指定在SQL盲注时如何解析和比较HTTP响应页面的内容。

		--level=LEVEL 执行测试的等级（1-5，默认为1）

		--risk=RISK 执行测试的风险（0-3，默认为1）

		--string=STRING 查询时有效时在页面匹配字符串

		--regexp=REGEXP 查询时有效时在页面匹配正则表达式

		--text-only 仅基于在文本内容比较网页

		Techniques（技巧）：这些选项可用于调整具体的SQL注入测试。

		--technique=TECH SQL注入技术测试（默认BEUST）

		--time-sec=TIMESEC DBMS响应的延迟时间（默认为5秒）

		--union-cols=UCOLS 定列范围用于测试UNION查询注入

		--union-char=UCHAR 用于暴力猜解列数的字符

		Fingerprint（指纹）：

		-f, --fingerprint 执行检查广泛的DBMS版本指纹

		Enumeration（枚举）：这些选项可以用来列举后端数据库管理系统的信息、表中的结构和数据。此外，您还可以运行您自己的SQL语句。

		-b, --banner 检索数据库管理系统的标识

		--current-user 检索数据库管理系统当前用户

		--current-db 检索数据库管理系统当前数据库

		--is-dba 检测DBMS当前用户是否DBA

		--users 枚举数据库管理系统用户

		--passwords 枚举数据库管理系统用户密码哈希

		--privileges 枚举数据库管理系统用户的权限

		--roles 枚举数据库管理系统用户的角色

		--dbs 枚举数据库管理系统数据库

		--tables 枚举的DBMS数据库中的表

		--columns 枚举DBMS数据库表列

		--dump 转储数据库管理系统的数据库中的表项

		--dump-all 转储所有的DBMS数据库表中的条目

		--search 搜索列（S），表（S）和/或数据库名称（S）

		-D DB 要进行枚举的数据库名

		-T TBL 要进行枚举的数据库表

		-C COL 要进行枚举的数据库列

		-U USER 用来进行枚举的数据库用户

		--exclude-sysdbs 枚举表时排除系统数据库

		--start=LIMITSTART 第一个查询输出进入检索

		--stop=LIMITSTOP 最后查询的输出进入检索

		--first=FIRSTCHAR 第一个查询输出字的字符检索

		--last=LASTCHAR 最后查询的输出字字符检索

		--sql-query=QUERY 要执行的SQL语句

		--sql-shell 提示交互式SQL的shell

		Brute force（蛮力）：这些选项可以被用来运行蛮力检查。

		--common-tables 检查存在共同表

		--common-columns 检查存在共同列

		User-defined function injection（用户自定义函数注入）：这些选项可以用来创建用户自定义函数。

		--udf-inject 注入用户自定义函数

		--shared-lib=SHLIB 共享库的本地路径

		File system access（访问文件系统）：这些选项可以被用来访问后端数据库管理系统的底层文件系统。

		--file-read=RFILE 从后端的数据库管理系统文件系统读取文件

		--file-write=WFILE 编辑后端的数据库管理系统文件系统上的本地文件

		--file-dest=DFILE 后端的数据库管理系统写入文件的绝对路径

		Operating system access（操作系统访问）：这些选项可以用于访问后端数据库管理系统的底层操作系统。

		--os-cmd=OSCMD 执行操作系统命令

		--os-shell 交互式的操作系统的shell

		--os-pwn 获取一个OOB shell，meterpreter或VNC

		--os-smbrelay 一键获取一个OOB shell，meterpreter或VNC

		--os-bof 存储过程缓冲区溢出利用

		--priv-esc 数据库进程用户权限提升

		--msf-path=MSFPATH Metasploit Framework本地的安装路径

		--tmp-path=TMPPATH 远程临时文件目录的绝对路径

		Windows注册表访问：这些选项可以被用来访问后端数据库管理系统Windows注册表。

		--reg-read 读一个Windows注册表项值

		--reg-add 写一个Windows注册表项值数据

		--reg-del 删除Windows注册表键值

		--reg-key=REGKEY Windows注册表键

		--reg-value=REGVAL Windows注册表项值

		--reg-data=REGDATA Windows注册表键值数据

		--reg-type=REGTYPE Windows注册表项值类型

		General（一般）：

		这些选项可以用来设置一些一般的工作参数。

		-t TRAFFICFILE 记录所有HTTP流量到一个文本文件中

		-s SESSIONFILE 保存和恢复检索会话文件的所有数据

		--flush-session 刷新当前目标的会话文件

		--fresh-queries 忽略在会话文件中存储的查询结果

		--eta 显示每个输出的预计到达时间

		--update 更新SqlMap

		--save file保存选项到INI配置文件

		--batch 从不询问用户输入，使用所有默认配置。

		Miscellaneous（杂项）：

		--beep 发现SQL注入时提醒

		--check-payload IDS对注入payloads的检测测试

		--cleanup SqlMap具体的UDF和表清理DBMS

		--forms 对目标URL的解析和测试形式

		--gpage=GOOGLEPAGE 从指定的页码使用谷歌dork结果

		--page-rank Google dork结果显示网页排名（PR）

		--parse-errors 从响应页面解析数据库管理系统的错误消息

		--replicate 复制转储的数据到一个sqlite3数据库

		--tor 使用默认的Tor（Vidalia/ Privoxy
```

## 16、Burp Suite重放包怎么做？

```text
发送到Repeater
```

## 17、对POST请求用户名密码爆破发送到哪里？

```text
发送到Intruder
```

## 18、越权漏洞有了解么

```text
水平越权:

也可以把其称作访问控制攻击漏洞.Web应用程序在接收到用户的请求时，我们在增删改查某条数据时候，没有判断数据所对应的用户，

或者在判断数据的用户时是通过从用户表单参数中获取userid来实现的，这里的话我们可以修改userid来实现水平越权。

垂直越权：

垂直越权又叫做权限提升攻击，具体原因就是web应用没有做用户权限控制，或者只是在菜单上做了权限控制，

导致恶意用户只要猜测到其他管理页面的URL，就可以访问或者控制其他角色拥有的数据或者页面，达到权限提升的目的。
```

## 19、有哪些上传绕过的方式？

```text
1.客户端js验证

2.服务器端验证

3.  配合文件包含漏洞

4.  配合服务器解析漏洞绕过

5.  配合操作系统文件命令规则

6.  CMS、编辑器漏洞

7.  配合其他规则

8.  WAF绕过

9.  文件后缀名绕过

10. 文件内容头校验（gif89a）

11. 文件头content-type字段校验（image/gif）
```

## 20、window的安全日志在哪里？

```text
电脑桌面右键单击此电脑，选中管理，进入管理界面，点击事件查看器，接着展开windows日志选项，windows日志界面点击安全选项卡，进入安全日志列表，可以记录所有电脑安全审核动作
```

## 21、linux中怎么查看系统日志

```text
在/var/log中
```

## 22、如何查看被入侵后敲过的命令？

```text
History
```

## 其他一些面试问题

1 linux 添加 删除 修改 复制一个文件

2 windows linux 最高权限是什么

3 路由器和交换机有什么区别 （自我介绍说成网络工程师了。。）

4 windows 域 和 域控

5 sql注入的危害 和 如何修复

6 sql注入如何拿到shell

7 什么是xss

8 文件上传漏洞 文件上传到哪了

9 文件上传漏洞 怎么拿到shell

10 使用脏牛时 把服务器系统搞蓝屏了怎么办

11除了教学的方式 还有哪些获取知识的方式

12经过这段时间的学习 你今后对哪些方向感兴趣

13擅长的技能 未来的意向

14 csrf与xss区别

15 linux 查找文件

16 除了教学的方式 还有哪些获取知识的方式

17语言接触过哪些?

18扫过什么网站

19给你个靶机能按照文档否找出靶机漏洞

20在助学基地学习了什么？

21你有系统学习网络安全方面的知识吗？

22什么叫全双工，什么叫半双工？

23学过什么渗透工具？

24御剑的主要功能？

25 bp爆破模块？

26爆破四种模式？简述过程

27 sql注入类型？

28抓包怎么区分包头，包体，正文？

29 sqlmap -u -r 区别

30 python和php能用到什么程度

31三次握手

32自己怎么挖掘到的漏洞，具体的步骤

33 linux的日志文件在哪里

34 怎么linux查看进程

35 拿到shell以后 3389没有打开，不能直接用命令打开3389，怎么远程连接

36 给你一个网站 ，你应该做些什么

37 linux怎么查看今天创建过什么历史文件

38 流量监控 是怎么监控的

39 kali的 ms17010

40 sql注入 说一下怎么查看数据库

41 sql注入除了手动 还有什么方法查看sql注入

42 sql注入怎么绕过waf的语句

43 sql的注入经常使用什么手法

------

原文链接：https://admin-root.blog.csdn.net/article/details/105566880