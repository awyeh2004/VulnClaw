# AI 安全题的代码片段

配套 `ctf-ai` SKILL.md。这里只放能直接粘进 `python_execute` 的东西。

## 1. 模型文件体检

```python
import pathlib, torch, pickletools

p = "model.pth"
print("size", pathlib.Path(p).stat().st_size)

# 结构（weights_only=True 时非张量对象会报错，这本身就是线索）
try:
    obj = torch.load(p, map_location="cpu", weights_only=True)
    print("weights_only OK, type:", type(obj))
except Exception as exc:
    print("weights_only FAILED:", type(exc).__name__, str(exc)[:200])
    obj = torch.load(p, map_location="cpu", weights_only=False)

if isinstance(obj, dict):
    for k, v in obj.items():
        print(f"{k:50} {getattr(v, 'shape', type(v))} {getattr(v, 'dtype', '')}")

# pickle opcode：看 GLOBAL/REDUCE 引用了谁
with open(p, "rb") as fh:
    head = fh.read(4096)
for line in pickletools.genops(head) if False else []:
    pass
try:
    pickletools.dis(open(p, "rb").read())
except Exception as exc:
    print("dis failed:", exc)
```

## 2. 权重里翻字符串 / ASCII 串

```python
import numpy as np, torch

def scan(obj, depth=0, path=""):
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            scan(v, depth + 1, f"{path}.{k}")
        return
    arr = None
    if hasattr(obj, "detach"):
        arr = obj.detach().cpu().numpy()
    elif isinstance(obj, np.ndarray):
        arr = obj
    if arr is not None and arr.dtype.kind in "iu":
        flat = arr.ravel()[:20000]
        if flat.size and flat.min() >= 30 and flat.max() <= 126:
            print("ASCII-like", path, arr.shape)
            print(bytes(flat.astype(np.uint8))[:200])

scan(obj)
```

`strings model.onnx | grep -iE 'flag|ctf'` 常常一步到位：onnx 的 protobuf 里名字是明文。

## 3. ONNX 元数据与输入名

```python
import onnxruntime as ort
sess = ort.InferenceSession("model.onnx", providers=["CPUExecutionProvider"])
print("inputs:", [(i.name, i.shape, i.type) for i in sess.get_inputs()])
print("outputs:", [(o.name, o.shape) for o in sess.get_outputs()])
print("meta:", sess.get_modelmeta().custom_metadata_map)
```

## 4. PGD 模板（白盒对抗样本）

```python
import torch

def pgd(model, x, target, eps=8/255, step=2/255, iters=40):
    model.eval()
    x = x.clone().detach()
    lo, hi = x - eps, x + eps
    for _ in range(iters):
        x.requires_grad_(True)
        loss = torch.nn.functional.cross_entropy(model(x), target)
        g, = torch.autograd.grad(loss, x)
        x = (x - step * g.sign()).clamp(lo, hi).clamp(0, 1).detach()
    return x
```

判据务必与题面一致：L∞ 用 `eps` 上限，L2 要算范数，按像素数限制就统计 `(x_adv != x).sum()`。

## 5. 成员推断 / 置信度阈值

```python
with torch.no_grad():
    logits = model(x)
    p = logits.softmax(-1)
    margin = p.topk(2).values.diff(dim=-1).abs()
    loss = torch.nn.functional.cross_entropy(logits, y)
# 训练集内的样本通常 margin 更大、loss 更小
```

## 6. 输入预处理对齐（最容易翻车）

```python
from torchvision import transforms
tf = transforms.Compose([transforms.Resize(224), transforms.ToTensor(),
                         transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])])
```
题面若给的是"0–255 的 uint8 数组"，先确认模型训练时是否做了 Normalize；不确定就把两种都试一遍，比较输出置信度——差一个量级就说明喂错了。

## 7. APK / dex（智能终端方向，工具已在）

```python
# APK 就是 zip：先看结构
import zipfile
z = zipfile.ZipFile("app.apk")
print([n for n in z.namelist() if n.endswith((".so", ".dex", ".json", ".txt"))][:20])
z.extract("classes.dex", "out")

# androguard（已安装，纯 python，不需要 jadx）
from androguard.core.dex import DEX
d = DEX(open("out/classes.dex", "rb").read())
for s in d.get_strings():
    t = str(s)
    if any(k in t.lower() for k in ("flag", "ctf", "password", "secret")):
        print(t)
```
native 里的 flag 更常见：`strings out/lib/arm64-v8a/*.so | grep -i flag`。
