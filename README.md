# autoMonitor
@Author：fe1w0

针对QAX skyeye 的 自动处理脚本：
1. 自动标灰已提交事件
2. 警告危险攻击

基本功能：
- [x] 登录检测和配置文件
- [x] 自动标灰无效攻击
	- [x] 已上报的攻击
	- [x] 多线程处理
- [x] ⚠️  警告威胁攻击
	- [x] 代码执行
	- [x] 命令执行
	- [x] webshell利用
	- [x] webshell上传
	- [x] SQL注入
	- [x] 暴力猜解
	- [x] 可自定义添加
- [x] 优化
	- [x] 忽视 已上报的攻击
	- [x] 忽视 白名单中的ip 
	- [x] 优化 终端界面
		- [x] 从终端当前页面第一行输出新的报告
		- [x] 支持其他平台
			- [x] Mac
			- [x] Linux
			- [x] Windows
- [x] 配置文件
	- [x] 认证信息配置，即Cookie
	- [x] 白名单 设置
	- [x] 已上报攻击 设置

基本使用，修改config/config.yaml配置即可。
每次使用前，需要先设置好session，之后csrf_token会自动刷新。
Windows平台使用时，推荐Windows Terminal终端，否则`console.clear()`会失效。

```bash
pip install rich HackRequests pyyaml

```
