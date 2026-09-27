# envelope-key-rotation-go

本地信封加密与主密钥轮换服务。用本地密钥存储（`internal/keystore`）模拟密钥管理后端（KMS），
在其上提供信封加密服务（`internal/envelope`），保证密钥版本变更、权限差异与并发轮换下的
加解密结论一致且可解释。

## 架构

```
调用方 (caller)
   │  Encrypt / Decrypt
   ▼
internal/envelope   信封服务：生成一次性 DEK、编码/解码信封格式
   │  WrapCurrent / Unwrap（主密钥材料不出 keystore）
   ▼
internal/keystore   本地密钥存储：版本生命周期、权限域、原子轮换与回滚
```

- **DEK（数据密钥）**：每次加密随机生成 32 字节，用 AES-256-GCM 保护明文，使用后清零。
- **主密钥版本**：每个版本持有独立的 32 字节 AES-256 主密钥，仅用于包装/解包 DEK；
  主密钥材料永不离开 `keystore` 包，对外只有 Wrap/Unwrap 语义。

## 信封格式

二进制线格式（大端序）：

```
magic(4) | wireVer(1) | keyVersion(4) | wrappedDEKLen(2) | wrappedDEK | nonce(12) | ciphertext
"EKR1"       1          主密钥版本号                       nonce||AES-GCM(DEK)   DEK 的 GCM nonce   AES-GCM(plaintext)
```

- `keyVersion` 记录加密时所用的主密钥版本；**解密时严格按此字段选择主密钥**，与当前版本无关。
- `Parse` 可只解码头部查看版本号而不解密。

## 密钥版本与轮换语义

版本生命周期：`ENABLED → DISABLED → DESTROYED`

| 状态 | 加密（Wrap） | 解密（Unwrap） |
|---|---|---|
| ENABLED | ✅ | ✅ |
| DISABLED | ❌ `ErrVersionDisabled` | ✅（既有密文仍可解） |
| DESTROYED | ❌ `ErrVersionDestroyed` | ❌ `ErrVersionDestroyed` |

- **轮换（Rotate）**：生成新版本（ENABLED）并原子切换为当前版本，旧版本置 DISABLED。
  轮换后既有密文仍按各自记录的版本正常解密，新写入一律使用新的当前版本。
- **原子性**：加密的"取当前版本 + 包装 DEK"由 `WrapCurrent` 在同一把锁内完成；
  轮换的"建版本 + 继承授权 + 切换当前版本"也在同一把锁内完成。
  并发读写不会看到部分更新或中间态。
- **回滚**：轮换提交前可注入失败（`SetRotateHook`，用于测试/模拟后端故障）。
  失败时删除待提交的新版本、回收其授权、恢复原当前版本——既有数据的可解密性不变。
- **销毁（Destroy）**：不可逆，密钥材料清零；其保护的历史数据按既定策略不再可解，
  解密返回 `ErrVersionDestroyed`，与"未知版本"（`ErrUnknownVersion`）可区分。

## 权限模型

- 每个 `envelope.Service` 绑定一个调用方身份（权限域），如 `"alice"`、`"bob"`。
- 调用方只能使用被显式授权（`Grant`）的密钥版本；`Revoke` 撤销授权。
- 越权的加密/解密一律返回 `ErrPermissionDenied`，与版本状态类错误可区分。
- 轮换时新版本自动继承旧当前版本的授权集合，保证被授权调用方连续可用。

## 错误分类（均可用 errors.Is 判定）

| 错误 | 含义 |
|---|---|
| `keystore.ErrUnknownVersion` | 密文记录的版本不存在 |
| `keystore.ErrVersionDisabled` | 版本已停用，禁止加密（仍可解密） |
| `keystore.ErrVersionDestroyed` | 版本已销毁，加解密均禁止 |
| `keystore.ErrPermissionDenied` | 调用方对该版本无授权 |
| `keystore.ErrNoActiveVersion` | 无可用当前版本，无法加密 |
| `keystore.ErrInvalidState` | 非法状态迁移（如对 DESTROYED 再操作） |
| `envelope.ErrMalformedEnvelope` | 信封字节无法解析 |
| `envelope.ErrUnsupportedWire` | 不支持的线格式版本 |
| `envelope.ErrDecryptFailed` | 密文完整性校验失败（被篡改） |

## 本地验证

```bash
# 全部测试（含 -race 竞态检测）
go test ./... -race -count=1

# 查看判定日志：每个用例打印涉及的密钥版本与判定依据
go test ./... -race -count=1 -v
```

覆盖的关键场景：

- `TestConcurrentRotationAndIO` / `TestConcurrentRotationWithEnvelopeIO`：
  8 个并发写协程 + 5 次并发轮换，验证无部分更新/中间态可见，结果确定。
- `TestRotateFailureRollsBack` / `TestRotationRollbackPreservesDecryptability`：
  注入轮换失败，验证整体回滚且既有密文可解密性不变。
- `TestDisableThenEncryptRejectedDecryptAllowed` / `TestDecryptUnknownAndDestroyedVersion`：
  版本停用/销毁/未知后的解密结论与可区分的错误原因。
- `TestPermissionDenied` / `TestPermissionDomains`：越权访问被拒绝且原因可区分。
