---
layout: post
title: ab压测工具结果的一些说明记录
tags: ab 压测
categories: other
published: true
---

## 压测示例
```sh
ab -n 1000 -c 200 http://url.cn  
```
`-n 1000` : 1000个请求  
`-c 200` : 200并发执行

## 压测结果部分说明
### Concurrency Level: 100
并发请求数

### Time taken for tests: 50.872 seconds
整个测试持续的时间

### Complete requests: 1000
完成的请求数

### Failed requests: 0
失败的请求数

### Total transferred: 13701482 bytes
整个场景中的网络传输量

### HTML transferred: 13197000 bytes
整个场景中的HTML内容传输量

### Requests per second: 19.66 [#/sec] (mean)
吞吐率，大家最关心的指标之一，相当于 LR 中的每秒事务数，后面括号中的 mean 表示这是一个平均值

### Time per request: 5087.180 [ms] (mean)
用户平均请求等待时间，大家最关心的指标之二，相当于 LR 中的平均事务响应时间，后面括号中的 mean 表示这是一个平均值

### Time per request: 50.872 [ms] (mean, across all concurrent requests)
服务器平均请求处理时间，大家最关心的指标之三


### Transfer rate: 263.02 [Kbytes/sec] received
平均每秒网络上的流量，可以帮助排除是否存在网络流量过大导致响应时间延长的问题
