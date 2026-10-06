# 本地信封加密与主密钥轮换服务

用本地密钥存储（`kms.Store`）模拟密钥管理后端，实现信封加密、主密钥版本轮换、
历史密文换保（迁移）、版本生命周期管理与调用方权限域。
纯 Go 标准库实现（AES-256-GCM），无外部依赖。

## 包结构

| 包 | 职责 |
|---|---|
| `kms` | 本地密钥存储：主密钥版本、生命周期、原子轮换、Wrap/Unwrap；主密钥材料不对外暴露 |
| `envelope` | 信封加解密与换保：随机 DEK 保护明文，主密钥版本包装 DEK；密文记录密钥版本 |
| `service` | 服务入口：调用方权限域校验、轮换/停用/销毁编排、密文记录存储与批量迁移 |

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
- **失效版本不可加密是硬约束**：所有加密路径（`Encrypt`、换保的目标版本）
  都经 `Wrap`，而 `Wrap` 只接受 ENABLED 版本；停用/销毁版本无论从哪条
  对外路径都无法参与加密或解包。销毁不可逆，重复销毁返回
  `ErrAlreadyDestroyed`，与首次销毁结果可区分。
- 停用/销毁的若是活跃版本，活跃指针回退到最近创建的 ENABLED 版本；无可用版本时
  加密报 `ErrNoActiveVersion`。

## 历史密文换保（迁移）

轮换只影响新写入，历史密文仍由旧版本保护。换保把一份已存在的密文从旧版本
迁移到指定的、当前可用（ENABLED）的新版本上，让旧版本能够安全退役：

```go
svc := service.New(store, envelope.NewCodec(store))

cph, _ := svc.Encrypt(caller, []byte("payload")) // 由 v1 保护
svc.Records().Put("doc1", cph)                   // 登记到记录存储
svc.Rotate("v2")                                 // 轮换

res := svc.Migrate("doc1", "v2")                 // 单条换保 v1 -> v2
// res.Migrated=true, res.FromVersion="v1", res.ToVersion="v2"

results := svc.MigrateBatch([]string{"doc1", "doc2"}, "v2") // 批量换保
```

语义保证：

- **明文不变**：换保是“解出明文 → 在目标版本下重新加密”，迁移前后解出的
  明文逐字节一致，仅保护版本改变（`envelope.Codec.ReWrap`）。
- **原子性**：`Service.Migrate` 的“读旧密文 → 换保 → 替换记录”在记录级
  临界区内完成，要么全部生效，要么保持原值——不存在迁移到一半、
  再也解不开的中间态。
- **幂等**：记录已在目标版本时迁移是空操作（`MigrateResult.Migrated=false`），
  失败重试不会重复生效或造成错乱。
- **失败安全**：目标版本停用/销毁、源版本已销毁等错误都会使记录保持原值，
  错误可经 `errors.Is` 区分，修正条件后重试即可。
- **并发安全**：迁移以单条记录为原子单位，可与正在进行的轮换、并发写入
  同时发生而互不破坏（`TestMigrateConcurrentWithRotation`，`-race` 验证）。
- **批量**：`MigrateBatch` 逐条独立结算，单条失败不影响其他记录，
  返回与输入等长、顺序一致的结果切片，按 `Err` 字段挑出失败项重试。

迁移完成后，旧版本即可停用并销毁：已迁移记录照常可解，未迁移密文按
原版本规则结算（可解则解，版本销毁后报 `ErrVersionDestroyed`）。

## 轮换后的读取兼容范围

| 调用方 | 加密 | 解密 |
|---|---|---|
| 空授权集（普通调用方） | 跟随当前活跃版本 | 任何**当前仍可解**的版本（ENABLED/DISABLED） |
| 显式授权集 | 集合内含活跃版本才可加密 | 仅集合内的版本 |

- 普通调用方在轮换后仍能解开自己此前用当时合法版本写入的密文——
  版本号变化不构成越权。
- 真正越权（显式授权集不含密文版本）仍返回 `service.ErrPermissionDenied`。
- 版本已销毁/不存在时，无论哪种调用方都由 kms 层返回
  `ErrVersionDestroyed` / `ErrUnknownVersion`——“没有权限”与“版本已失效”
  始终是两条独立、可区分的判定路径（权限判定先于密钥操作）。

错误一览：

| 情形 | 错误 |
|---|---|
| 版本不存在 | `kms.ErrUnknownVersion` |
| 版本停用但尝试加密/作为迁移目标 | `kms.ErrVersionDisabled` |
| 版本已销毁 | `kms.ErrVersionDestroyed` |
| 重复销毁 | `kms.ErrAlreadyDestroyed` |
| 无可用活跃版本 | `kms.ErrNoActiveVersion` |
| 调用方越权 | `service.ErrPermissionDenied` |
| 迁移目标记录不存在 | `service.ErrUnknownRecord` |

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
- `envelope.TestReWrap`：换保后明文不变、幂等空操作、停用/销毁版本不能
  作为换保目标、源版本销毁后已换保密文不受影响；
- `service.TestConcurrentRotation`：写方与多轮轮换锁步交错并发，断言每份密文
  记录的都是已提交版本且全部可解密（无中间态）；
- `service.TestRotationFailureRollback`：轮换失败后活跃版本与历史数据不变；
- `service.TestDecryptAfterInvalidation`：停用可解、销毁不可解；
- `service.TestPermissionDomains`：普通调用方轮换后读取兼容、显式授权集
  越权拒绝，且权限错误与版本失效错误可区分；
- `service.TestMigrateBasic`：单条换保、明文不变、旧版本销毁后已迁移记录
  可解而未迁移密文报版本失效；
- `service.TestMigrateBatch`：批量迁移逐条独立结算、目标不可用整批失败但
  记录保持原值、修正后重试成功且幂等、未知记录错误可区分；
- `service.TestMigrateConcurrentWithRotation`：迁移与多轮轮换、并发写入
  同时进行，最终全部记录汇聚到目标版本且明文不丢不错；
- `service.TestMigrateRetryAndHardConstraints`：失效版本不能作为迁移目标、
  失败不破坏原记录、重试幂等不重复生效、重复销毁结果可区分。

`-v` 日志会打印每个断言涉及的密钥版本及其判定依据（如
`v1 DESTROYED -> 解密拒绝 ErrVersionDestroyed`、并发版本分布 map、
迁移结果 `{ID:doc1 FromVersion:v1 ToVersion:v2 Migrated:true}` 等）。
