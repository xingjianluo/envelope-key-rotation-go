# 本地信封加密与主密钥轮换服务

用本地密钥存储（`kms.Store`）模拟密钥管理后端，实现信封加密、主密钥版本轮换、
版本生命周期管理与调用方权限域。纯 Go 标准库实现（AES-256-GCM），无外部依赖。

## 包结构

| 包 | 职责 |
|---|---|
| `kms` | 本地密钥存储：主密钥版本、生命周期、原子轮换、Wrap/Unwrap；主密钥材料不对外暴露 |
| `envelope` | 信封加解密：随机 DEK 保护明文，主密钥版本包装 DEK；密文记录密钥版本 |
| `service` | 服务入口：调用方权限域校验、轮换/停用/销毁编排 |

## 信封格式

每次加密：

1. 取当前**活跃**主密钥版本（ENABLED）；
2. 随机生成 32 字节数据密钥 DEK（AES-256）；
3. `kms.Store.Wrap(version, DEK)`：用主密钥版本以 AES-GCM 包装 DEK，主密钥材料不离开 Store；
4. 用 DEK 以 AES-GCM 加密明文，AAD 绑定密钥版本 ID。

密文结构（`envelope.Cipher`）：

```
KeyVersion  string  包装 DEK 所用主密钥版本 ID（明文元数据，用于选版本）
WrappedDEK  []byte  nonce || AES-GCM_wrapped(DEK)，AAD=KeyVersion
Nonce       []byte  DEK 加密随机数
Ciphertext  []byte  AES-GCM(plaintext)，AAD=KeyVersion
```

解密时**严格依据密文记录的 `KeyVersion`** 选择主密钥版本解包 DEK，再解密明文。
密文不携带、任何接口也不返回主密钥材料。

## 密钥版本与轮换语义

版本生命周期：`ENABLED → DISABLED → DESTROYED`。

| 状态 | 加密（Wrap） | 解密（Unwrap） |
|---|---|---|
| ENABLED | ✅ | ✅ |
| DISABLED | ❌ `ErrVersionDisabled` | ✅（历史数据可解） |
| DESTROYED | ❌ `ErrVersionDestroyed` | ❌（不可逆，材料清零） |

- **轮换**：`Store.Rotate(newID, hook)` 在单个互斥临界区内完成
  “创建新版本 + 执行 hook + 切换活跃指针”。并发读写永远观察不到中间态：
  活跃指针要么指向旧版本，要么指向已完整创建的新版本。
- **失败回滚**：hook 返回错误时，新版本从存储中删除，活跃指针不变，
  既有数据可解密性不变（`TestRotationFailureRollback`）。
- **向后兼容**：轮换后旧密文仍按记录的版本解密，新写入一律使用新活跃版本。
- 停用/销毁的若是活跃版本，活跃指针回退到最近创建的 ENABLED 版本；无可用版本时
  加密报 `ErrNoActiveVersion`。

## 权限模型

调用方 `Caller{Domain, AllowedVersions}`：

- `AllowedVersions` 为空：仅允许**当前活跃版本**（跟随轮换）；
- 非空：仅允许集合中的版本。

加密要求调用方被授权活跃版本；解密要求被授权**密文记录的版本**。
越权返回 `service.ErrPermissionDenied`，与版本层错误可经 `errors.Is` 区分：

| 情形 | 错误 |
|---|---|
| 版本不存在 | `kms.ErrUnknownVersion` |
| 版本停用但尝试加密 | `kms.ErrVersionDisabled` |
| 版本已销毁 | `kms.ErrVersionDestroyed` |
| 重复销毁 | `kms.ErrAlreadyDestroyed` |
| 无可用活跃版本 | `kms.ErrNoActiveVersion` |
| 调用方越权 | `service.ErrPermissionDenied` |

权限校验先于密钥操作，但不会主动探测版本存在性；因此越权与版本失效是两条
独立、可区分的判定路径。

## 本地验证

```bash
go build ./...
go test -race -v ./...        # -race 验证并发安全，-v 打印密钥版本与判定依据
```

测试覆盖：

- `kms.TestVersionLifecycle`：启用/停用/销毁的加解密结论与可区分错误；
- `kms.TestRotateRollback`：轮换失败整体回滚；
- `envelope.TestEncryptDecryptAcrossRotation`：轮换前后加解密、停用可解、
  销毁/未知版本拒绝；
- `service.TestConcurrentRotation`：写方与多轮轮换锁步交错并发，断言每份密文
  记录的都是已提交版本且全部可解密（无中间态）；
- `service.TestRotationFailureRollback`：轮换失败后活跃版本与历史数据不变；
- `service.TestDecryptAfterInvalidation`：停用可解、销毁不可解；
- `service.TestPermissionDomains`：越权拒绝，且权限错误与版本失效错误可区分。

`-v` 日志会打印每个断言涉及的密钥版本及其判定依据（如
`v1 DESTROYED -> 解密拒绝 ErrVersionDestroyed`、并发版本分布 map 等）。
