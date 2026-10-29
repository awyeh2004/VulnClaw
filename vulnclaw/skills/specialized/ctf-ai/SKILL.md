---
name: ctf-ai
description: CTF 人工智能安全 — 模型文件逆向（.pt/.pth/.onnx/.pkl 结构与 pickle 反序列化风险）、对抗样本（FGSM/PGD，白盒与查询式黑盒）、模型窃取、成员推断、后门检测与触发词、训练数据里找 flag、agent/prompt 注入；给出可执行的 torch/onnxruntime 判据
routing:
  target_types: [ctf]
  task_types: [ctf]
---

# CTF 人工智能安全知识库

强网杯这类比赛把"人工智能"单列为一个方向。题型集中在这几类，**先判给的是什么**再动手：

| 手上有什么 | 题型 | 去哪 |
|---|---|---|
| 模型文件（`.pt`/`.pth`/`.onnx`/`.h5`/`.pkl`/`.joblib`） | 模型逆向 / 后门检测 / 权重里找 flag | 第 1、2 节 |
| 推理接口（提交输入拿输出） | 对抗样本 / 模型窃取 / 成员推断 | 第 3、4、5 节 |
| 训练数据或日志 | 数据里藏 flag / 后门触发词 | 第 2 节末 |
| prompt / agent 控制台 | prompt 注入、工具滥用 | 第 6 节 |

## 1. 先看模型文件本身，别急着推理

```python
import torch, pathlib
p = "model.pth"
print(pathlib.Path(p).stat().st_size)
sd = torch.load(p, map_location="cpu", weights_only=True)   # 先试 weights_only
print(type(sd))
if isinstance(sd, dict):
    for k, v in list(sd.items())[:20]:
        print(k, getattr(v, "shape", type(v)))
```

判据：
- **`weights_only=True` 报错** → 文件里有非张量对象（这正是 pickle 反序列化题的入口，见下条），改 `weights_only=False` 但**先看清环境**；
- 键名里有 `fc`/`head`/`classifier` → 最后一层，flag 常藏在这一层的权重或 bias 里；
- 键名里出现 `backdoor`/`trigger`/`extra`/可疑自定义层名 → 后门题，直接往那个层找。

**pickle 反序列化**：`.pt`/`.pkl`/`.joblib` 都是 pickle。恶意模型会在 `__reduce__` 里放命令。做题时反向利用：`pickletools.dis(open(p,'rb').read())` 看 opcode，找 `GLOBAL`/`REDUCE` 引用的函数名——flag 或被劫持的目标就在那里。

## 2. flag 藏在权重/数据里

依次查（成本从低到高）：
1. `strings model.pth | grep -i flag` —— 权重文件里常直接躺着字符串（尤其自定义 Dataset 被打包进去时）；
2. 遍历 state_dict，找**异常来源**：某个键的形状与网络结构不匹配、dtype 是 int64/uint8 而非 float、值域像 ASCII（30–126）→ 当字节串解；
3. `torch.load` 出来的 dict 里除了 `state_dict` 还有 `epoch`/`optimizer`/`config` 等，逐个 `str()` 打印；
4. ONNX：`onnx` 未装时用 `onnxruntime` 的 `InferenceSession(...).get_modelmeta()`，或直接 `strings model.onnx`（onnx 的 protobuf 里字符串是明文）。

## 3. 对抗样本（给推理接口，要"骗过"模型）

白盒（有权重）：
```python
# FGSM
x.requires_grad_(True)
loss = criterion(model(x), target_label)
loss.backward()
x_adv = (x + eps * x.grad.sign()).clamp(0, 1)
```
```python
# PGD（更强，迭代 + 投影）
for _ in range(steps):
    x.requires_grad_(True)
    loss = criterion(model(x), target)
    g, = torch.autograd.grad(loss, x)
    x = (x - step * g.sign()).clamp(x - eps, x + eps).clamp(0, 1).detach()
```
黑盒（只有输出）：迁移攻击（在本地同类模型上生成）、查询式打分攻击（估计梯度）、边界攻击（只改一个像素反复试探）。

**判据**：题目要求的通常是"让模型输出指定类别且扰动量小于阈值"，flag 由服务端在成功时返回。扰动量的度量要与题目一致（L∞ 逐像素最大 / L2 范数 / 改动像素数），否则会被判超限。

## 4. 模型窃取 / 成员推断

- **窃取**：用查询结果训练替代模型，题目验证的是"替代模型与原模型在测试集上的吻合率"。输入分布要覆盖决策边界（随机 + 边界附近采样）。
- **成员推断**：同一批样本，训练集内的置信度/损失系统性更低。给一个样本判"在不在训练集"，用 logit 间隔或 loss 阈值即可。

## 5. 后门检测

症状：正常输入准确率高，但带某个**触发词/图案**时全部输出攻击者指定的类。
- 有训练代码/数据：搜可疑的数据增强、`if trigger in text:` 之类的分支；
- 只有权重：看最后一层某个类的权重是否有异常大的正偏移（"捷径"），或 BatchNorm 的 running_mean 有离群值；
- 触发词常是低频 token 或特定 unicode；可对词表逐个 token 试替换，看输出是否翻转。

## 6. prompt 注入 / agent 题

本库已有专门笔记：搜 `lookup_playbook` 关键词「prompt 注入 间接 injection 工具滥用」。要点是**载荷放在被读取的内容里**（文件、网页、工具返回值），不是直接对模型说；判据通常是让 agent 调用某个不该调的工具或泄露系统提示。

## 常见坑（都会让"看起来跑通"其实是错的）

- **归一化**：训练用 `ToTensor()+Normalize(mean,std)` 而题里给 0–255，直接喂进去准确率会像随机，误判成"模型不对"；
- **eval 模式**：忘了 `model.eval()`，BatchNorm/Dropout 让同一输入输出漂移；
- **通道顺序**：PIL 是 RGB，cv2 是 BGR；
- **ONNX 输入名**：`sess.get_inputs()[0].name` 才是正确键，别写死 `input`；
- **扰动度量**：见第 3 节判据，最容易在这一步被判超限。

## 本机已装的 AI 安全工具（直接可用，2026-10-30 已验证）

拿到可疑模型文件时，**先扫再分析**，这两个扫描器已经装好并在 PATH 上：

```
modelscan --path model.pth      # 序列化攻击扫描（.pkl/.pt/.joblib/.h5）
picklescan --path model.pkl     # pickle 危险 opcode（eval/os.system/__reduce__）
```

实测：含 `eval` 的恶意 pickle 会被判 `dangerous import 'builtins eval' FOUND`；
干净文件报 `No issues found!`。扫描无命中≠安全（只认已知危险模式），但命中即实锤。

**对抗样本用 `adversarial-robustness-toolbox`（ART 1.20，已装）**，别手写攻击循环：

```python
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
from art.estimators.classification import PyTorchClassifier
clf = PyTorchClassifier(model=model, loss=nn.CrossEntropyLoss(),
                        input_shape=(3,224,224), nb_classes=N, clip_values=(0.0,1.0))
adv = ProjectedGradientDescent(estimator=clf, eps=8/255, eps_step=2/255,
                               max_iter=40).generate(x_numpy)
```

ART 同一个库还带模型窃取（`CopyCatCNN`/`FunctionallyEquivalentExtraction`）与
成员推断（`MembershipInferenceBlackBox`）攻击实现——那两类题先查它，不必从论文复现。

## 参考

- `references/ai-challenge-recipes.md` — 可复制的代码片段（模型结构打印、权重转字节、PGD 模板、ONNX 元数据）
- 相关笔记：`lookup_playbook` 搜「prompt 注入」「模型文件 pickle」
- GitHub 项目档案：`E:\vulnclaw\work\GH-SCAN-20261029.md`（两轮 345 个仓库，按分支分桶）
