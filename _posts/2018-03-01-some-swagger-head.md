---
layout: post
title: swagger中的一些参数记录
tags: swagger
categories: other
published: true
---

## paramType：参数放在哪个地方
```
· header --> 请求参数的获取：@RequestHeader
· query --> 请求参数的获取：@RequestParam
· path（用于restful接口）--> 请求参数的获取：@PathVariable
· body（不常用）
· form（不常用）
· formData --> 放在body的form中
```
![屏幕快照 2019-11-29 上午10.39.54.png](https://i.loli.net/2019/11/29/oWfy3pTKvHBXDVb.png)

## field type : 参数类型
```
string
file
```