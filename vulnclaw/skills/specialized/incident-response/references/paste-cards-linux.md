# 粘贴卡 · Linux（应急响应，网页终端用）

> **为什么有这张卡**：IR references 里全是分面长文档，而平台网页终端**可能不支持长
> 粘贴**、甚至可能不支持多行。这张只放**逐行可粘贴**的短命令，每条尽量短。
>
> **怎么用**：一次粘**一行**（`##` 开头的是标题、粘进去也无害，shell 当注释）。
> 顺序：先 0→2（十分钟内能圈定可疑面），再按线索挑 3→6。**全部只读**，
> 不要在被入侵机器上写入/下载任何东西（除了你自己的取证输出）。
>
> **哪些要 root**：1/2/3 的部分命令要 root（`/proc/*/exe`、`/etc/shadow`、auth.log）；
> 拿不到就跳过，别停在这里。

## 0. 现场固定（先跑，建立时间基准）

```
date -u; hostname; id; uname -sr
cat /etc/os-release | head -3
uptime; w
```

## 1. 进程与网络（最快出线索）

```
ps -eo pid,ppid,user,etime,args --sort=start_time | tail -25
ps aux | grep -v grep | grep -Ei 'nc |ncat|socat|python|perl|php|jsp'
ss -tunap | head -40
netstat -tunap 2>/dev/null | head -40
ls -l /proc/*/exe 2>/dev/null | grep -i deleted
ls -l /proc/*/cwd 2>/dev/null | grep -Ei '/tmp|/dev/shm'
```

## 2. 持久化（webshell/后门最爱）

```
crontab -l 2>/dev/null; ls -l /etc/cron* /var/spool/cron/ 2>/dev/null
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null
systemctl list-units --type=service --state=running --no-pager | head -25
ls -la /etc/rc.local /etc/init.d/ 2>/dev/null | head -20
ls -lat /etc/systemd/system/*.service 2>/dev/null | head -15
grep -rE 'bash -i|/dev/tcp|curl .*\| *sh' /etc /var/www 2>/dev/null | head
cat ~/.bashrc ~/.bash_profile /root/.bashrc 2>/dev/null | grep -vE '^#|^$'
```

## 3. 账号与登录

```
awk -F: '$3>=1000||$3==0{print $1,$3,$6,$7}' /etc/passwd
awk -F: '$2!="x"&&$2!="*"&&$2!="!"{print $1}' /etc/shadow 2>/dev/null
grep -E ':0:' /etc/passwd
last -a 2>/dev/null | head -15
lastb 2>/dev/null | head -10
tail -100 /var/log/auth.log 2>/dev/null || tail -100 /var/log/secure
grep -aiE 'Accepted|Failed password' /var/log/auth.log 2>/dev/null | tail -20
```

## 4. 文件与时间线（按时间圈定比全盘搜准）

```
ls -la --time-style=full-iso /tmp /dev/shm /var/tmp 2>/dev/null | head -40
find /var/www /tmp /dev/shm -type f -newermt '-2 days' -ls 2>/dev/null | head -30
find / -xdev -perm -4000 -newermt '-10 days' -type f -ls 2>/dev/null | head
find / -xdev -name '.*' -newermt '-1 day' -type f -ls 2>/dev/null | head -20
grep -rlE 'eval\(|base64_decode|system\(|assert\(' /var/www 2>/dev/null | head
ls -lat /var/www/**/*.php 2>/dev/null | head -15
ls -la ~/.ssh /root/.ssh 2>/dev/null; cat ~/.ssh/authorized_keys 2>/dev/null
```

## 5. 日志

```
tail -200 /var/log/syslog 2>/dev/null || tail -200 /var/log/messages
grep -aiE 'POST .*\.(php|jsp|asp)' /var/log/nginx/access.log 2>/dev/null | tail -20
grep -aiE 'union select|<script|\.\./' /var/log/nginx/access.log 2>/dev/null | tail -20
zcat -f /var/log/*.gz 2>/dev/null | grep -ai 'flag{' | head
journalctl -n 200 --no-pager 2>/dev/null
```

## 6. 找隐藏 flag（题目要求"找隐藏的 flag"时）

```
grep -rIl 'flag{' / 2>/dev/null | head -20
find / -xdev -iname '*flag*' 2>/dev/null | head -20
grep -rIl 'flag{' /var/log /etc /root /home /opt /srv 2>/dev/null | head -20
env | sort
cat /proc/1/environ 2>/dev/null | tr '\0' '\n'
history 2>/dev/null | tail -30; cat ~/.bash_history /root/.bash_history 2>/dev/null | tail -30
ls -la / /root /home/* 2>/dev/null | grep -iE 'flag|secret|key|backup|\.zip|\.7z'
```

## 搜不到时（体面收尾，别硬耗）

```
find / -xdev -size -4k -type f -newermt '-3 days' 2>/dev/null | head -40
grep -rIl 'flag' /var/www /opt 2>/dev/null | head -20
find / -xdev \( -name '*.txt' -o -name '*.log' -o -name '*.bak' \) -newermt '-3 days' 2>/dev/null | head -30
```

> 编码变形（`flag{` 被 base64/hex/大小写打散）见 `references/flag-landing-spots.md`；
> 内存与流量见 `references/50-memory-traffic.md`。**搜不到就记录已排查范围**，
> 别把"没找到"当"不存在"。
