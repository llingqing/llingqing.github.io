---
title: cachyos
published: 2026-07-14
updated: 2026-07-14
slug: cachyos
image: api
tags: [linux,niri,双系统,cachyos]
category: linux
draft: false
---
在开源 Linux 发行版生态中，基于 Arch Linux 的衍生系统始终以高度定制化和极致性能深受爱好者青睐，CachyOS 便是其中的佼佼者。作为一款主打 “Blazingly Fast & Customizable” 的 Linux 发行版，CachyOS 从设计之初便以**为用户提供更出色的运行速度、更可靠的安全性与更便捷的使用体验**为核心目标，既继承了 Arch Linux 滚转更新、高度可定制的核心优势，又通过全链路的性能优化，解决了原生 Arch Linux 安装繁琐、需手动优化的痛点。

CachyOS 为不同层级的 Linux 用户量身打造，无论是初次接触 Linux 的新手，还是拥有丰富使用经验的资深玩家，都能在这款系统中找到适配自身的使用方式 —— 新手可通过友好的图形化安装器快速部署，无需复杂的手动配置；进阶用户则能借助丰富的定制化选项，从内核调度器、软件包编译到桌面环境进行全方位个性化设置。其凭借优化内核、高性能编译包、多元的桌面选择与灵活的安装方式，成为追求极速体验、注重系统定制性用户的理想选择。详情可看官方 Wiki [为什么选择 CachyOS？](https://wiki.cachyos.org/cachyos_basic/why_cachyos/)

本教程将从安装前准备、核心安装步骤、系统设置优化到故障排查进行全方位讲解，助力大家解锁 CachyOS 的极致性能。
##  安装前准备
- 不少于8G的U盘
- win11镜像（[win11](https://www.microsoft.com/zh-cn/software-download/windows11）)
![1784017763328076938.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784017774889_1784017763328076938.png)
- cachyos镜像（cachyos 的官网：[https://cachyos.org/](https://cachyos.org/) 在页面点击 download 即可跳转下载页面）
![dms_capture_1784017837620.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784017843223_dms_capture_1784017837620.png)
- winPE(用来制作windows启动盘[winpe](https://www.wepe.com.cn/download.html))
- rufus(用来制作cachyos启动盘)[rufuus](https://rufus.ie/zh/))
:::warning
务必检查镜像是否损坏!!!
windows：
1. 在 PowerShell 中，使用  Get-FileHash cmdlet 计算下载的 ISO 文件的哈希值。例如：
        Get-FileHash C:\Users\user1\Downloads\Contoso8_1_ENT.iso
2.在下载页面对比hash值
cachyos：
[说明](https://wiki.cachyos.org/cachyos_basic/download/)
:::
## 安装windows11

打开winpe,将U盘格式化
![dms_capture_1784018890653.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784018903814_dms_capture_1784018890653.png)
然后将两个镜像和rufus移入格式化完成后的U盘，准备重装win11
:::warning
注意事项
1. 需在 bios 中关闭安全启动并设置 U 盘启动。(联想是Fn+F2)
2. 安装 Windows 和 Linux 双系统时 Windows 必须关闭快速启动、休眠功能、Windows BitLocker，同时最好不要把两个系统安装在同一块硬盘，防止 Windows 更新把 Linux 的启动项删除。
:::
完成上一步后，直接重启进入bios，更改UEFI启动顺序：将你的U盘移至最上（一般名称是EFI USB Device).
然后保存并退出，进入启动盘系统界面
### 格式化与分区
:::warning
格式化之前务必备份好个人重要数据！！！
:::
打开分区工具DiskGenius->右键硬盘->删除所有分区(请确保分区格式为GUID格式)->保存更改->新建分区（windows启动分区），按图示选择
![dms_capture_1784019896888.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784019903675_dms_capture_1784019896888.png)
然后新分区大小根据自己的硬盘大小来，这个新分区就作为C盘来使用了
保存更改并退出
然后打开windows安装器，选择U盘中的win11镜像
![dms_capture_1784020261756.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784020275725_dms_capture_1784020261756.png)
可引导驱动器选择刚刚建立的windows启动分区
安装驱动器的位置选择C盘
选项选择win11专业版即可
接下来进入优化调整界面，根据自己的需求选择即可
![dms_capture_1784020461818.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784020472094_dms_capture_1784020461818.png)
最后点击安装，直接继续->重启
windows重装部分就到这里了。
## 安装cachyos
安装好windows，并做好基础设置后，将U盘中的cachyos镜像和rufus拖到桌面
打开rufus，按图示选择，引导类型选择cachyos的镜像
![dms_capture_1784020932934.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784020951701_dms_capture_1784020932934.png)
然后点击开始->OK,当状态变绿后，直接重启电脑，注意将U盘的启动顺序移至最上
然后就自动进入cachyos的安装界面了
![dms_capture_1784021249591.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784021272717_dms_capture_1784021249591.png)
先进行换源，接下来要下载依赖
![dms_capture_1784021393380.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784021400866_dms_capture_1784021393380.png)
进入终端复制以下内容
```shell
sudo bash -c 'echo "Server = https://mirrors.ustc.edu.cn/cachyos/repo/\$arch/\$repo" > /etc/pacman.d/cachyos-mirrorlist && echo "Server = https://mirrors.ustc.edu.cn/cachyos/repo/\$arch_v3/\$repo" > /etc/pacman.d/cachyos-v3-mirrorlist && echo "Server = https://mirrors.ustc.edu.cn/cachyos/repo/\$arch_v4/\$repo" > /etc/pacman.d/cachyos-v4-mirrorlist && echo "Server = https://mirrors.ustc.edu.cn/archlinux/\$repo/os/\$arch" > /etc/pacman.d/mirrorlist'
```
接着回到安装程序上，按照下面的步骤开始设置
1. 地区选择 Asia，区域选择 Shanghai
2. 键盘布局一般选默认  
3. 引导这里选 GRUB 即可，其他的具体查看官方 Wiki [Offered Boot Managers](https://wiki.cachyos.org/installation/boot_managers/)  
### 分区
在 **Partitons** 步骤（即分区界面）时选择你想安装的硬盘，点击手动分区。  
如果点击手动分区后无法点击创建，编辑和删除，点击左边的新建分区表。选择第二个 GPT  
首先创建第一个分区：（这个分区存放 Linux 引导，防止 Windows 更新把 Linux 删除了，Linux 更新不会删除 Windows 引导）  
大小：512MB  
文件系统： FAT32  
挂载点： /boot/efi  
标志： boot

然后创建第二个分区，这个分区是储存分区，可以把剩下空间全分给它
文件系统： BTRFS（也可以其他类型，具体查看 [Filesystems](https://wiki.cachyos.org/installation/filesystem/)） 
挂载点： /  
标志： 可不选

1. 桌面环境选择niri。不熟悉 Linux 可以选择默认 **KDE Plasma**，界面和操作逻辑与 win 类似。详情查看 [Desktop Environments](https://wiki.cachyos.org/installation/desktop_environments/)  
**不推荐同时安装多个桌面环境！！！ **
2. 有打印机的需求需要勾选 Printing-Support 和 Support for HP Printer/Scanner  
3. 设置密码
接下来就一直下一步，安装部分耐心等待即可。
## 系统基本设置
成功安装系统后会默认打开 Cachy OS Hello 程序，在右下角可以取消开机自启动（在开始菜单的系统分类可以重新打开）。推荐先点击更新系统（**Cachy os 属于滚动式更新，建议不要长时间不更新**）  
点击 “**应用 / 调整**”，勾选 cachy update（期间会提示输入管理员密码），这是托盘上的更新提醒助手，推荐开启。  
**游戏用户**可以点击下方的 **Install Gaming packages**，这个可以一键安装游戏环境。（包含 STEAM 和 Lutris 等）  
在前面的步骤我们已经设置了国内镜像源，如果没有设置或者失效了可以点击此页面的 “**排序镜像**” 即可自动选择速度最快的软件源
![dms_capture_1784022879121.png](https://tu.lingluoa.dpdns.org/file/obsidian/1784022889901_dms_capture_1784022879121.png)
### 安装AUR、flatpack、shelly
```shell
sudo pacman -S paru # 最主流的 AUR（Arch 用户仓库）助手，解决 Arch 官方仓库没有的软件包安装问题，支持自动处理依赖、编译源码
sudo pacman -S flatpack（真神）
sudo pacman -S shelly（现代化的Arch linux包管理器，可以在这里下到clash、qq等）
```
### gurb配置
```shell
sudo vim /etc/default/grub
```
修改启动等待时间：GRUB_TIMEOUT=5（默认为 5 秒，可改为 10 秒，方便选择系统）
双系统添加 Windows，确保 GRUB_DISABLE_OS_PROBER=false（取消注释，让 GRUB 检测其他系统）
保存退出后，执行命令更新 GRUB，在终端输入以下代码
```shell
sudo grub-mkconfig -o /boot/grub/grub.cfg
```
重启系统，GRUB 菜单会显示 Windows 启动项，可上下选择。
### 安装输入法

CachyOS 未预装中文输入法，推荐安装 **Fcitx5**。

```shell
sudo paru -S fcitx5-im fcitx5-chinese-addons
```
安装完成后还需要修改环境变量，使用 **vim** 打开 **/etc/environment** 后输入以下内容
```txt
XMODIFIERS=@im=fcitx 
```
保存成功后我们需要注销用户，再次登录后打开设置，找到键盘设置项，按如图设置  
至此，输入法安装完成
到这里双系统安装就结束了，之后可能会出niri的美化。
参考博客：
[仙仙客栈](https://blog.drxian.cn/archives/715)