# 05 — Windows / IIS 基线加固

> 改 RDP/防火墙前确认还有控制台/平台 VNC 通道，别把自己关在外面。

## 1. 账户与密码策略

```cmd
net user
net localgroup administrators
net accounts
```

```powershell
# 密码策略（最小长度、有效期、锁定）
net accounts /minpwlen:12 /maxpwage:90 /lockoutthreshold:5 /lockoutduration:15

# 禁用 Guest
net user guest /active:no

# 重命名 Administrator（题目要求时；可能影响检查器，先看题目）
wmic useraccount where name='Administrator' call rename name='AdminX'
```

## 2. SMB

```powershell
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Get-SmbShare
# 删除不必要的共享
Remove-SmbShare -Name SHARE -Force
```

补丁（MS17-010 等）：

```cmd
wmic qfe list brief
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

## 3. RDP

```powershell
# 不用就关
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

# 要用：开 NLA、限制用户、防火墙只放行必要来源
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True -Profile Domain,Private
```

## 4. 防火墙

```powershell
Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block
# 按需放行
New-NetFirewallRule -DisplayName 'Allow HTTP' -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
```

## 5. 不必要服务

```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name,DisplayName
# 常见可关：RemoteRegistry、Telnet、FTPSVC、SNMP、Spooler（不打印时）
Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled
```

> 不要关检查器要用的 IIS/WinRM/RDP；先看题目。

## 6. IIS

```powershell
# 版本头/详细错误
appcmd set config /section:httpProtocol /removeServerHeader:true
appcmd set config /section:httpErrors /errorMode:DetailedLocalOnly

# 目录浏览
appcmd set config "Default Web Site" /section:directoryBrowse /enabled:false

# 关闭 WebDAV（不用时）
appcmd set config /section:system.webServer/security/requestFiltering /allowDoubleEscaping:false
Uninstall-WindowsFeature Web-DAV-Publishing
```

删除默认页/示例：

```powershell
Remove-Item 'C:\inetpub\wwwroot\iisstart.htm' -ErrorAction SilentlyContinue
Remove-Item 'C:\inetpub\wwwroot\welcome.png' -ErrorAction SilentlyContinue
```

## 7. 目录权限

```cmd
icacls C:\inetpub\wwwroot
:: 去掉 Everyone/Users 写权限；只给 IIS_IUSRS 读+执行
icacls C:\inetpub\wwwroot /inheritance:r /grant:r "IIS_IUSRS:(OI)(CI)(RX)" /grant:r "Administrators:(OI)(CI)F"
```

Flag 文件：

```cmd
icacls C:\flag.txt /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F"
```

## 8. 审计

```cmd
auditpol /set /category:* /success:enable /failure:enable
```

PowerShell 日志（按题目/域策略）：

```powershell
# 启用脚本块日志
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1
```

## 9. 验证

```powershell
net accounts
net localgroup administrators
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature
Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction
Get-Service RemoteRegistry | Select Status,StartType
icacls C:\inetpub\wwwroot
```

```bash
curl -sI http://TARGET/ | grep -Ei 'server|x-powered-by|x-aspnet-version'
```

## 10. 常见翻车点

- 关 RDP/防火墙前没有备用通道。
- 改 Administrator 名字导致检查器登录失败。
- 只改 IIS 配置没 `iisreset`/重启站点。
- `icacls` 去掉了 IIS_IUSRS 读权限，站点 500。
- 关 SMBv1 后老应用/检查器连不上；题目明确要求关才关。
