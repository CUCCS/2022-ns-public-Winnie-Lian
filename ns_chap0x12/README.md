# chap0x12

## 实验目的
- 了解zeek的使用
- 尝试用zeek来自动化分析取证
- 了解完整的取证分析过程

## 实验要求
- [x] 使用 zeek 来完成取证分析

## 实验环境
- 虚拟机
  - kali
  - docker-zeek_lts
    - Linux 25b324c171a5 5.18.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.18.5-1kali6 (2022-07-07) x86_64 GNU/Linux
    - zeek version 5.0.2

## 实验过程

### 环境配置

进入zeek官网，发现已经有发布docker，于是顺理成章的抛弃实验指南中的源代码安装方式（这也算是官方安装了

怎么说，现在看到刚刚更新的都有心理阴影了，属于是ptsd了😥
![](./img/faredate.png)
还是上 LTS_release 吧
![](img/lts_release.png)
```bash
docker pull zeekurity/zeek:lts # 拉取镜像
docker run -it zeekurity/zeek:lts # 启动容器
```
![](img/docker_up.png)

查看实验环境
```sh
cat /etc/os-release
# PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
# NAME="Debian GNU/Linux"
# VERSION_ID="11"
# VERSION="11 (bullseye)"
# VERSION_CODENAME=bullseye
# ID=debian
# HOME_URL="https://www.debian.org/"
# SUPPORT_URL="https://www.debian.org/support"
# BUG_REPORT_URL="https://bugs.debian.org/"
uname -a
# Linux 25b324c171a5 5.18.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.18.5-1kali6 (2022-07-07) x86_64 GNU/Linux
zeek -v
# zeek version 5.0.2
```
![](img/zeek_os_release.png)
![](img/zeek_env.png)

然后为了方便之后对于文本的编辑，安装一个vim
```bash
apt update
apt install vim -y
```
![](img/no_vim.png)
![](img/install_vim.png)

用 vim 编辑 /usr/local/zeek/share/zeek/site/local.zeek ，在文件尾部追加两行新配置代码
```sh
@load frameworks/files/extract-all-files
@load mytuning.zeek
```
![](img/append.png)

在 /usr/local/zeek/share/zeek/site 目录下创建新文件 mytuning.zeek ，追加内容为：
```sh
# redef ignore_checksums = T;
# 追加也可以直接放进去嘛
echo "redef ignore_checksums = T;" >> mytuning.zeek
cat mytuning.zeek # 确认一下
```
![](img/append2.png)

用`docker cp <src_path> <dst_path>`把课程提供的要分析的包传入容器
![](img/docker_cp.png)

利用zeek自动化分析
```sh
zeek -r attack-trace.pcap /usr/local/zeek/share/zeek/site/local.zeek
```
在 attack-trace.pcap 文件的当前目录下会生成一些 .log 文件和一个 extract_files 目录，在该目录下我们会发现有一个文件
![](img/zeek.png)
![](img/extrac.png)

接着再把提取出来的文件从容器中传出来
![](img/dockerps.png)
本来想放在宿主机上上传  virustotal 分析，结果，刚 copy 过来，就被宿主机的火绒安全软件杀掉了，这也算是对火绒的一次考验吧哈哈哈，通过考验
![](img/huorong.png)
![](img/huorong1.png)

于是在 kali 中直接上传分析吧
![](img/virustotal.png)
发现匹配了一个 历史扫描报告 ，该报告表明这是一个已知的后门程序！至此，基于这个发现就可以进行逆向倒推，寻找入侵线索了

通过阅读 /usr/local/zeek/share/zeek/base/files/extract/main.zeek 的源代码
![](img/find_id.png)
可以看到上图中框出来的部分，在extract_filename中，最右字段是一个id值，FHUsSu3rWdP07eRE4l 是 files.log 中的文件唯一标识
![](img/fid.png)
查看 file.log ，可以看到对应的通信主机ip
![](img/hosts.png)

同时，查看 conn.log ，不仅可以看到ip，也可以看到通信协议为tcp，提供服务的是ftp服务（文件传输)
![](img/ftp.png)

利用 zeek-cut 可以更加优雅的查看日志
![](img/tips.png)
![](img/tips2.png)

用相应的方法查看 ftp.log 
![](img/ftplog.png)
![](img/passwordhidden.png)
可以看到 password 默认是 hidden 状态，通过在 /usr/local/zeek/share/zeek/site/mytuning.zeek 中增加以下变量重定义来实现显示查看 password
```sh
echo "redef FTP::default_capture_password = T;" >>/usr/local/zeek/share/zeek/site/mytuning.zeek
```
![](img/passwd.png)

---
**发疯的分割线**
> 已经忘记之前在干嘛了，打开就写了这些，以及img中多余的内容同理，但为了警醒自己的愚蠢，就留在这里以作警示吧


先按照官方文档中的来一遍试试
![](img/pre.png)
```bash
sudo apt-get install cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
```
既然教材中给出的也是通过source安装，那就源文件来一遍吧，先从官方链接中获取到了.deb文件（官方还是没有提供kali来着)
![](img/deb.png)
先学习一些dpkg来着，看后面应该要配置一下，所以先unpack就行了吧
```bash
dpkg --help
dpkg -i zeek
```
然后好像有点问题，然后在过程中，看到有kali用apt安装的，于是check一下，19年8月移除之后，万一现在有了呢
![](img/apt-install.png)

```sh
# 大概查找一下
apt search zeek
# 现在应该是这个 zeek-lts

# 详细查看一下
apt info zeek-lts
# Package: zeek-lts
# Version: 5.0.4-0
# Status: install ok unpacked
# Priority: optional
# Section: Network
# Maintainer: Johanna Amann <johanna@icir.org>
# Installed-Size: 360 kB
# Depends: zeek-lts-core (= 5.0.4-0), zeekctl-lts (= 5.0.4-0), zeek-lts-core-dev (= 5.0.4-0), zeek-lts-spicy-dev (= 5.0.4-0), zeek-lts-zkg (= 5.0.4-0), zeek-lts-client (= 5.0.4-0)
# Download-Size: unknown
# APT-Manual-Installed: yes
# APT-Sources: /var/lib/dpkg/status
# Description: Zeek is a powerful framework for network analysis and security monitoring.
#就是 5.0.4 ，那就省心了吧

sudo apt install zeek-lts
```