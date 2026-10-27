# hooklens

**单文件零依赖 webhook 透镜：抓包 / 验签 / 重放 / 转发，一个 .py 文件全部搞定。**

调试 webhook 时你是不是也这样：在服务端日志里 `print(request.body)`，签名对不对靠猜，想重放一次得重写 curl 命令拼引号。hooklens 把这条链路补齐：

```
python3 hooklens.py serve --port 8080 --secret-env WHSEC --webhookmode
```

这一条命令起了一个本地接收器：每个打过来的 webhook 都落进 JSONL 台账（含原始字节、header、body 的 sha256），**同时实时验 HMAC 签名**——假签名回 400 并给出理由（`sig-mismatch` / `timestamp-skew 3600s > 300s`），真签名回 200。

## 为什么是 hooklens

- **零依赖**：纯 Python 标准库，Python 3.8+ 直接跑。服务器上没有 pip 权限也能用
- **验签引擎覆盖两大流派**：GitHub 式 `sha256=<hex>` 前缀、Stripe 式 `t=<ts>,v1=<hex>`（签名载荷 `t=<ts>.<body>`）；hex/base64/base64url 三种编码自动尝试；sha1/sha256/sha384/sha512 全支持
- **时间戳防重放**：`t=` 或时间戳 header 偏差超过 `--max-skew`（默认 300s）直接拒绝
- **字节级重放**：`replay --entry N` 把抓到的第 N 条原样（byte-identical）重发给任意目标，`bytes_identical: true` 写进输出
- **密钥卫生**：密钥走 `--secret-env` 环境变量不进 argv；所有输出只有掩码 `whse...2c81`；JSONL 台账里永无密钥
- **离线验签**：`verify` 子命令吃 body 文件 + headers 文件，退出码 0/1，直接接 CI 门禁

## 60 秒上手

### 1. 起一个带验签的接收器

```bash
export WHSEC=你的webhook密钥
python3 hooklens.py serve --port 8080 --secret-env WHSEC \
  --webhookmode --sig-header Stripe-Signature
```

把平台的回调地址临时指到 `http://你的机器:8080/webhook`，打过来的每一条都实时验签+落盘。只想看内容不验签就去掉 `--secret-env`（或用 `receive` 子命令）。

### 2. 离线验一条签名（CI 友好）

```bash
hooklens verify --secret-env WHSEC \
  --body-file payload.bin --headers-file headers.txt \
  --sig-header Stripe-Signature --webhookmode
```

输出一行 JSON：`{"verdict": "OK", "matched": {"alg": "sha256", "encoding": "hex"}, "ts_delta_seconds": 0, ...}`；验不过退出码 1。`--strict-ts` 时缺时间戳头也判失败。

### 3. 原样重放第 N 条

```bash
hooklens replay --log hooklens.jsonl --entry 2 --target http://127.0.0.1:9000
# {"result": "REPLAYED", "status": 200, "bytes_identical": true}
```

`--dry-run` 先看将发什么不发真请求。修复了消费端代码之后重放，不用再去平台后台点「Redeliver」。

### 4. 转发/压测时自动签名

```bash
hooklens send --url http://127.0.0.1:9000/hook --body-file payload.bin \
  --secret "$WHSEC" --alg sha256
```

自动附加 `X-Timestamp` + `X-hooklens-Signature: sha256=<hex>` 两个头。

## 子命令一览

| 子命令 | 干什么 | 关键参数 |
|---|---|---|
| `receive` | 只抓包不验签 | `--port --log --limit --status --verbose` |
| `serve` | 抓包+实时 HMAC 验签 | `--secret-env --webhookmode --sig-header --ts-header --max-skew --strict-ts` |
| `verify` | 离线验签（文件/stdin） | `--secret-env --body-file --headers-file --alg --encoding` |
| `send` | 签名发送到任意 URL | `--url --body-file --header --secret --alg` |
| `replay` | 台账第 N 条字节级重放 | `--log --entry --target --dry-run` |
| `selftest` | 20 项不变量自测 | 无 |

`--limit N`：台账只保留最新 N 条（裁剪幂等），长期挂机不胀盘。`--status`：给平台伪造响应码（比如回 500 测它的重试退避策略）。

## 不变量（selftest 覆盖）

- **I1** receive 只写 JSONL；二进制负载自动转 base64 存储，永不写坏台账
- **I2** 任何子命令的输出/日志不出现原始密钥，只有首4+尾4掩码
- **I3** 重放字节恒等：收到什么发什么，`body_sha256` 收发两侧一致并写进输出
- **I4** verify/send/replay 失败退出码 1；receive 正常退出 0
- **I5** `--limit` 只裁最旧 N 条且幂等

自测含 RFC 4231 官方 HMAC 测试向量、GitHub/Stripe 双流派格式、篡改检测、过期时间戳、伪造错钥等对抗用例：**20/20 green**。另有偏态分布实测（100 条混合流量：88 正常 + 12 伪造）：**12/12 伪造全捕获、88/88 正常零误伤**。

```bash
python3 hooklens.py selftest
```

## 真实场景

- **「回调到底发没发过来」**：`receive --port 8080`，打开 `--verbose` 看 header+body 实时滚
- **「签名一直对不上」**：`verify` 会告诉你它命中的 alg/encoding 组合；对不上就给你 `sig-mismatch` 而不是沉默
- **「平台说重试了但消费者没收到」**：台账里翻那条记录，`replay` 到新起的服务上复现
- **「想测消费者的 5xx 处理」**：`receive --status 500`，平台的重试退避策略立刻现形
- **「签名周期性失败」**：`verify` 输出 `ts_delta_seconds`，时钟漂移一眼看穿

## 设计边界（诚实说）

- 单机内存友好但不是高性能网关：ThreadingHTTPServer 够调试用，别拿它接生产流量
- 只做 HMAC 家族签名，不做 RSA/ECDSA/JWS 验签（那是 oidcprobe 的活）
- 台账是 JSONL 不是数据库，百万级请自己轮转（`--limit` 是兜底不是替代）

## LICENSE

MIT
