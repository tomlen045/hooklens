# Changelog

## 1.0.0 - 2026-10-27

首个公开版本。

- `receive`：本地 HTTP 接收器，全方法捕获，JSONL 台账（body/二进制 b64/sha256/headers），`--limit` 幂等裁剪，`--status` 伪造响应码，`--verbose` 实时滚 header+body
- `serve`：抓包 + 实时 HMAC 强制验签（GitHub `sha256=` 前缀 / Stripe `t=,v1=` 双流派、hex/base64/base64url 自动、sha1~sha512、`--max-skew` 防重放、`--strict-ts`）
- `verify`：离线验签，body/headers 文件化，退出码 CI 门禁友好，输出 alg/encoding/ts_delta/secret_id（掩码）
- `send`：签名转发/压测发送（自动 X-Timestamp + X-hooklens-Signature），`--insecure` 自签 TLS，`--dry-run`
- `replay`：台账条目字节级重放，`bytes_identical` 写进输出，`--dry-run`
- `selftest`：20 项不变量（I1-I5），RFC 4231 官方向量，双流派+篡改+过期+错钥对抗用例，20/20 green
- 偏态分布实测：100 条混合流量（88 正常 4 算法 x 3 编码 + 12 伪造）12/12 捕获 0 误伤
