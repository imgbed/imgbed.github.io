---
layout: post
title: 小型网站渗透常规思路之抛砖引玉
tags: 基础知识 渗透 渗透思路
categories: 基础知识
published: true
---

首先，我们知道 。当我们得到一个目标后，当然目标只是针对小型网站的一个思路，大型网站又是另外一个思路了。



## 信息收集

首先要做的就是信息收集，正所谓磨刀不误砍柴功。 

以下引用[owasp 渗透指南4.0 版](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/frontispiece/README.html)



-   [搜索引擎信息发现和侦察 (OTG-INFO-001)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/conduct_search_engine_discovery_and_reconnaissance_for_information_leakage_otg-info-001.html)
-   [识别web服务器 (OTG-INFO-002)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/fingerprint_web_server_otg-info-002.html)
-   [web服务器元文件信息发现 (OTG-INFO-003)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/review_webserver_metafiles_for_information_leakage_otg-info-003.html)
-   [服务器应用应用枚举 (OTG-INFO-004)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/enumerate_applications_on_webserver_otg-info-004.html)
-   [评论信息发现 (OTG-INFO-005)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/review_webpage_comments_and_metadata_for_information_leakage_otg-info-005.html)
-   [应用入口识别 (OTG-INFO-006)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/identify_application_entry_points_otg-info-006.html)
-   [识别应用工作流程 (OTG-INFO-007)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/map_execution_paths_through_application_otg-info-007.html)
-   [识别web应用框架 (OTG-INFO-008)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/fingerprint_web_application_framework_otg-info-008.html)
-   [识别web应用程序 (OTG-INFO-009)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/fingerprint_web_application_otg-info-009.html)
-   [绘制应用架构图 (OTG-INFO-010)](http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/web_application_security_testing/map_application_architecture_otg-info-010.html)

 那我们简单说说常用搜集的一些信息

### google hacking

比如 利用google hacking 命令 找些敏感文件比如，site:xxx.com inurl:bak｜txt｜doc等信息 。 还有就是搜集二级域名和对应的ip ，当然我们这时候就需要区别是真实ip 还是cdn 了。 推荐猪猪侠的信息搜集神器： https://github.com/ring04h/wydomain  或者 http://fofa.so/lab/ips   根域名透视 、以及robots.txt 文件 等

####  



### 指纹之别 

识别对应的web 服务器，看是 **Apache，iis ，tomcat，jboss 等，以及使用的web 系统是否是常用的，比如dz，常用cms  ，wordpress 等 常用的通用程序 ，指纹识别出来了的话，就可以找找已经出来的cve ，看是否补丁及时打上，能否直接用cve 拿下。**



### **DNS 信息搜集**

**比如常见的DNS 域传送漏洞**



### **端口搜集**

**根据网站的真实ip ，用nmap 扫端口，看开放了哪些端口。 哪些端口是否可被利用，比如ssh，telnet，ftp， 以及某些测试系统的端口等。** 



### **后台敏感目录扫描**

**比如用御剑跑字典，跑一些敏感目录，比如fck 编辑器，后台目录，敏感界面等信息 ，这些信息都有可能帮助你直接拿下对方服务器**



### **网站目录结构爬取**

**比如对网站系统目录用burp suite 的 爬虫功能，爬基本的网站目录架构，把目录机构爬出来，在根据研发的那些思维猜后台、上传文件路径等。** 



## **漏洞扫描**



### **主机层扫描**

**这个不用说，直接把真实ip 丢nessus 里面去扫就够了，然后根据扫描出来的结果 结合 msf payload 直接打过去就可以了**



### **web漏洞扫描**

**比如，用awvs，netsparker 直接先过一遍 ，然后在根据经验手工看脆弱点，根据脆弱点来尝试不同的方式**



## **手工测试**

**常见测试以及漏洞组合拳比如常见的sql 注入测试，xss ，xxe漏洞，csrf ，文件上传等 然后根据前面收集的内容，以及扫描器的结果进行 综合筛选，然后进行利用，根据各种小细节进行漏洞尝试，以及根据多个小漏洞进行 组合利用，多个漏洞组合的攻击：比如前段时间在某银行进行测试的时候，有几个有意思的漏洞，一个漏洞是别名账号登入可被无限撞库（弱密码） ＋ 一个转账验证码漏洞绕过 。  那这两个漏洞结合起来，影响就大了。xss： 这个不用说，看能不能直接打管理员cookie 后台sql 注入： 数据库找敏感信息，比如管理员账号密码，或者直接根据权限，看能不能直接getshell 文件上传： 利用一些fck 等编辑器漏洞、iis 等的解析漏洞，以及程序校验不严格，直接上传马儿，getshell web框架漏洞： 比如strtus2 漏洞，spring mvc 的xxe 漏洞 等

弱密码爆破转了一圈，实在没能找出影响大的漏洞的话，那么我们试试后台密码爆破、以及ssh爆破、ftp 爆破等，这也是万万没办法的事情了，有时运气来了挡都挡不住，一不小心 弱密码爆破就直接进入后台了，进入了后台，后台一般安全性都比较弱，然后你懂的。
以上就是针对一些小网站的常规渗透思路，抛砖一下，引出大牛的玉。** 



---

原文链接: https://my.oschina.net/swrite/blog/400647