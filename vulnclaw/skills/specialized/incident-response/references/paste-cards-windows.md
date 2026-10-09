# 粘贴卡 · Windows（应急响应，网页终端用）

> 与 `paste-cards-linux.md` 同规矩：**一次粘一行**，`##` 行是标题（cmd 里会报错但无害，
> 或干脆别粘）。默认 shell 是 **cmd.exe**（不是 PowerShell），下面的 `&` 是 cmd 的连接符。
> 需要管理员权限的：`wevtutil`、`reg query HKLM`、`schtasks` 全量、`Get-WinEvent`。
>
> **cmd 的两个坑（实测）**：① `;` 不是命令分隔符，用 `&`；② `1>&2` 这类 POSIX 重定向
> 不成立。要复杂逻辑就显式写 `powershell -c "..."`。
>
> **已实测**（本机 Win11 23H2 / 22631，逐条跑过）：0 全部、1（`tasklist|findstr`、
> `wmic process`、`netstat`）、2（`reg query` ×3、`schtasks` ×2、两条含空格的 `dir`）、
> 5（`wevtutil`）。**教训两条**：① 多词过滤一律用引号无关的 `/C:词` 形式，否则
> 引号在传递中一丢就报 `FINDSTR: 无法打开 xxx`；② **递归搜索很慢** —— 本机
> `gci -Recurse` 扫 `%TEMP%` 实测 **271 秒**，别在刚进题时跑，也不要对整盘跑，
> 先缩到具体目录或加 `-Depth`。

## 0. 现场固定

```
whoami /all
hostname & systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time"
echo %DATE% %TIME% & wmic os get LastBootUpTime
```

## 1. 进程与网络（最快出线索，注意父子关系）

```
tasklist | findstr /I /C:powershell /C:wscript /C:cscript /C:mshta /C:rundll32 /C:certutil
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath /format:csv
netstat -ano | findstr LISTENING
netstat -anob | findstr /I /C:LISTENING /C:ESTABLISHED
```

## 2. 持久化（后门最爱这几处）

```
schtasks /query /fo LIST /v | findstr /I /C:TaskName /C:Task
schtasks /query /fo TABLE /nh | findstr /V "\\Microsoft\\"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f ImagePath /d | findstr /I /C:temp /C:appdata
dir /a /o:d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a /o:d "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

> 含空格的路径**必须带引号**（Web 终端若把引号吃掉会报"语法不正确"）：
> 那时先 `cd /d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` 再 `dir /a /o:d`。

## 3. 账号与登录

```
net user
net localgroup Administrators
query user
net accounts
wevtutil qe Security "/q:*[System[(EventID=4720 or EventID=4732)]]" /c:20 /rd:true /f:text
```

## 4. 文件与时间线（按时间圈定）

```
dir /a /s /o:d C:\Windows\Temp
dir /a /s /o:d "%TEMP%"
powershell -c "gci $env:TEMP -Recurse -File -EA 0 | ? LastWriteTime -gt (Get-Date).AddDays(-2) | select -F 30 FullName"
forfiles /P C:\inetpub\wwwroot /S /D -2 /C "cmd /c echo @path @fdate @ftime"
dir /a /s /o:d C:\inetpub\wwwroot | findstr /I /C:.asp /C:.aspx /C:.jsp /C:.php
powershell -c "gci C:\inetpub -Recurse -File -EA 0 | ? Length -lt 3000 | select -F 25 FullName"
```

> `forfiles` 的 `-C "cmd /c ..."` 是**嵌套引号**，最容易被终端吃掉（实测会报
> "／C 选项不能指定多于 1 次"）。它不行就用上面那条 PowerShell，效果一样。

## 5. 日志

```
wevtutil qe System /c:40 /rd:true /f:text | findstr /I "Error Warning"
wevtutil qe Application /c:40 /rd:true /f:text | findstr /I "Error Warning"
wevtutil qe Security "/q:*[System[(EventID=4624)]]" /c:20 /rd:true /f:text
dir C:\Windows\System32\winevt\Logs | findstr /I "Security System"
powershell -c "Get-WinEvent -LogName Security -MaxEvents 25 | ft TimeCreated,Id,Message -Auto"
```

## 6. 找隐藏 flag

```
findstr /S /I /M /C:"flag{" C:\inetpub\* C:\Windows\Temp\* "%TEMP%\*"
where /r C:\ *flag*
where /r C:\ *secret*
powershell -c "gci C:\ -Recurse -File -EA 0 | Select-String 'flag\{' -List | select -F 20 Path"
powershell -c "gci C:\Users,C:\ProgramData -Recurse -File -EA 0 | ? Length -lt 5000 | select -F 30 FullName"
```

## 搜不到时（体面收尾）

```
dir /a /s /o:d C:\ | findstr /I "flag secret key backup"
dir /s /b "%USERPROFILE%\Desktop" "%USERPROFILE%\Documents"
dir /a C:\ /o:d
powershell -c "gci $env:TEMP -R -File -EA 0|? LastWriteTime -gt (Get-Date).AddDays(-3)|% FullName"
powershell -c "gci C:\inetpub -R -File -EA 0|? LastWriteTime -gt (Get-Date).AddDays(-3)|% FullName"
```

> 编码变形（`flag{` 被 base64/hex/大小写打散）见 `references/flag-landing-spots.md`；
> Windows 落点表在该文件的 Windows 一节。**注意**：`cmd` 下 `;` 无效、POSIX 重定向无效，
> 上面每条都是按 cmd 写的；粘到 PowerShell 里要自己改用 `;`。
>
> 本机（笔记本）是工作台：解码、写脚本、出报告都在本机做，**受影响机器上只读**。
