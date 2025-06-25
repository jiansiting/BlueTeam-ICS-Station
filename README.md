**这是一个OT Blueteam用于Windows系统的上位机及内网自检工具。**

## 功能概述

这个工具集成了多种常用的功能，包括：
- 系统信息收集
- 网络信息收集
- 用户账户信息
- 文件操作
- 权限提升检测
- 网络扫描
- 安全产品检测
- 持久化功能

## 基本用法

```
BlueTeam-ICS-Station.bat -h           查看帮助信息
BlueTeam-ICS-Station.bat -w           查看系统进程
BlueTeam-ICS-Station.bat -all         一键内网信息收集
BlueTeam-ICS-Station.bat -kill 进程名  杀死指定进程
```

## 详细功能说明

### 信息收集

```
BlueTeam-ICS-Station.bat -ip          显示所有IP配置信息
BlueTeam-ICS-Station.bat -a           显示系统信息
BlueTeam-ICS-Station.bat -b           显示本地计算机上的所有服务
BlueTeam-ICS-Station.bat -c           显示计划任务的详细信息
BlueTeam-ICS-Station.bat -d           显示所有工作站统计信息
BlueTeam-ICS-Station.bat -e           显示本地计算机上的用户账户
BlueTeam-ICS-Station.bat -f           显示本地管理员组的成员
BlueTeam-ICS-Station.bat -g           显示所有监听端口和关联的进程信息
BlueTeam-ICS-Station.bat -i           显示本地计算机上的所有共享资源
BlueTeam-ICS-Station.bat -j           使用wmic显示所有共享资源的名称、路径和状态
BlueTeam-ICS-Station.bat -k           使用route print显示路由表
BlueTeam-ICS-Station.bat -l           使用arp -a显示所有ARP缓存条目
BlueTeam-ICS-Station.bat -m           使用whoami /all显示有关当前用户的详细信息
BlueTeam-ICS-Station.bat -n           显示工作站配置信息
BlueTeam-ICS-Station.bat -o           使用fsutil fsinfo drives显示所有可用驱动器
BlueTeam-ICS-Station.bat -dns         显示DNS解析器缓存
BlueTeam-ICS-Station.bat -firewall    显示所有防火墙规则
BlueTeam-ICS-Station.bat -procs       显示详细的进程信息，包括命令行
BlueTeam-ICS-Station.bat -creds       显示凭据管理器中保存的凭据
```

### 文件操作

```
BlueTeam-ICS-Station.bat -cc 源路径 目标路径    复制文件
BlueTeam-ICS-Station.bat -cv 源路径 目标路径    移动文件
BlueTeam-ICS-Station.bat -x 文件路径 内容       创建文件并写入内容
BlueTeam-ICS-Station.bat -v 目录路径           查看指定目录中的文件
```

### 高级功能

```
BlueTeam-ICS-Station.bat -ps "命令"            执行PowerShell命令
BlueTeam-ICS-Station.bat -download URL 保存路径  从URL下载文件
BlueTeam-ICS-Station.bat -persist 任务名 命令    创建计划任务以实现持久化
BlueTeam-ICS-Station.bat -privesc              检查权限提升机会
BlueTeam-ICS-Station.bat -netscan              扫描本地网络中的活动主机
BlueTeam-ICS-Station.bat -av                   检测系统上安装的安全产品
```

## 使用示例

### 基本信息收集
```
BlueTeam-ICS-Station.bat -ip
```
显示当前系统的IP配置信息，包括IP地址、子网掩码、网关等。

### 下载文件
```
BlueTeam-ICS-Station.bat -download http://abc.com/1.exe c:\temp\1.exe
```
从指定URL下载文件并保存到本地路径。

### 检查权限提升机会
```
BlueTeam-ICS-Station.bat -privesc
```
检查系统中可能存在的权限提升向量，如AlwaysInstallElevated注册表项、未引用的服务路径等。

### 创建持久化
```
BlueTeam-ICS-Station.bat -persist "BadTask" "c:\temp\1.exe"
```
创建一个名为"BadTask"的计划任务，在用户登录时执行指定命令。

### 扫描本地网络
```
BlueTeam-ICS-Station.bat -netscan
```
扫描本地网络中的活动主机和设备，并检查常见开放端口。

### 检测安全产品
```
BlueTeam-ICS-Station.bat -av
```
检测系统上安装的防病毒软件、EDR和其他安全产品。

## 注意事项

- 本工具仅用于授权的OT安全蓝队评估
- 在使用前请确保获得适当的授权
- 某些功能可能会触发安全产品的告警
- 建议在测试环境中先行测试功能
