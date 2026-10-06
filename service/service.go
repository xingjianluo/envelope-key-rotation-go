// Package service 组合密钥存储与信封加密，提供权限域与轮换语义。
package service

import (
	"errors"
	"fmt"

	"github.com/xingjianluo/envelope-key-rotation-go/envelope"
	"github.com/xingjianluo/envelope-key-rotation-go/kms"
)

// ErrPermissionDenied 表示调用方未被授权使用目标密钥版本。
var ErrPermissionDenied = errors.New("service: permission denied for key version")

// Caller 标识一个调用方及其被授权的密钥版本集合。
type Caller struct {
	Domain string
	// AllowedVersions 为允许使用的版本集合；为空表示仅允许当前活跃版本。
	AllowedVersions map[string]bool
}

func (c Caller) allows(versionID string, activeID string) bool {
	if c.AllowedVersions == nil {
		return versionID == activeID
	}
	return c.AllowedVersions[versionID]
}

// Service 是信封加密与轮换服务入口。
type Service struct {
	store *kms.Store
	codec *envelope.Codec
}

// New 创建服务。
func New(store *kms.Store, codec *envelope.Codec) *Service {
	return &Service{store: store, codec: codec}
}

// Encrypt 以调用方权限加密：一律使用当前活跃版本，且调用方须被授权该版本。
func (s *Service) Encrypt(c Caller, plaintext []byte) (*envelope.Cipher, error) {
	active, err := s.store.ActiveVersion()
	if err != nil {
		return nil, err
	}
	if !c.allows(active.ID, active.ID) {
		return nil, fmt.Errorf("%w: caller %q may not encrypt with version %q",
			ErrPermissionDenied, c.Domain, active.ID)
	}
	return s.codec.Encrypt(plaintext)
}

// Decrypt 以调用方权限解密：按密文记录的版本选择主密钥，
// 未知/已销毁版本由 kms 层拒绝，越权版本由本层拒绝，原因可区分。
//
// 读取兼容：未做逐版本授权的调用方（AllowedVersions 为空）在轮换之后
// 仍可解开"版本活跃期间合法写入、且当前仍可解"的历史密文；
// 从未活跃过的版本仍判越权，已销毁版本报版本失效错误而非权限错误。
func (s *Service) Decrypt(c Caller, cph *envelope.Cipher) ([]byte, error) {
	if cph == nil {
		return nil, fmt.Errorf("service: nil cipher")
	}
	if err := s.checkDecryptPermission(c, cph.KeyVersion); err != nil {
		return nil, err
	}
	return s.codec.Decrypt(cph)
}

// checkDecryptPermission 判定调用方是否有权解密指定版本的密文。
// 对未显式授权的调用方，先判定版本失效原因（未知/已销毁），
// 再判定是否"曾活跃"以区分越权，保证两类原因始终可区分。
func (s *Service) checkDecryptPermission(c Caller, versionID string) error {
	if c.AllowedVersions != nil {
		if !c.AllowedVersions[versionID] {
			return fmt.Errorf("%w: caller %q may not decrypt with version %q",
				ErrPermissionDenied, c.Domain, versionID)
		}
		return nil
	}
	// 空授权集：允许活跃版本及"曾经活跃且仍可解"的历史版本。
	v, err := s.store.Get(versionID)
	if err != nil {
		return err // ErrUnknownVersion
	}
	if v.State == kms.StateDestroyed {
		return fmt.Errorf("%w: %q", kms.ErrVersionDestroyed, versionID)
	}
	if !s.store.WasActive(versionID) {
		return fmt.Errorf("%w: caller %q may not decrypt with version %q",
			ErrPermissionDenied, c.Domain, versionID)
	}
	return nil
}

// Rotate 轮换主密钥：创建新版本并原子切换活跃指针。
// 轮换在密钥存储的临界区内完成，并发读写不会观察到中间态。
func (s *Service) Rotate(newVersionID string) error {
	return s.RotateWithHook(newVersionID, nil)
}

// RotateWithHook 同 Rotate，hook 在切换活跃指针之前执行；
// hook 返回错误则整体回滚：新版本被撤销，既有数据的可解密性不变。
func (s *Service) RotateWithHook(newVersionID string, hook func() error) error {
	_, err := s.store.Rotate(newVersionID, func(_ *kms.MasterKeyVersion) error {
		if hook != nil {
			return hook()
		}
		return nil
	})
	return err
}

// DisableVersion 停用版本：不再可用于加密，历史密文仍可解密。
func (s *Service) DisableVersion(id string) error { return s.store.Disable(id) }

// DestroyVersion 销毁版本（不可逆）：其保护的历史数据不再可解。
func (s *Service) DestroyVersion(id string) error { return s.store.Destroy(id) }

// MigrationResult 是单条密文的迁移结果：Cipher 与 Err 有且仅有一个非空。
type MigrationResult struct {
	Cipher *envelope.Cipher // 迁移成功的新密文（原密文不被修改）
	Err    error            // 迁移失败原因，可用 errors.Is 区分
}

// Migrate 把一份密文从当前记录版本换保到 targetVersion：
// 迁移后明文逐字节不变，改由目标版本保护；此后源版本即使停用/销毁，
// 已迁移的密文仍照常可解。
//
// 权限：调用方须对源版本有解密权、对目标版本有使用权（与 Encrypt 同规则）。
// 原子性：原密文原地不动，成功才返回新密文；任何失败都不会留下
// "迁移到一半"的状态，原密文保持可解，可安全重试（幂等）。
func (s *Service) Migrate(c Caller, cph *envelope.Cipher, targetVersion string) (*envelope.Cipher, error) {
	if cph == nil {
		return nil, fmt.Errorf("service: nil cipher")
	}
	if err := s.checkDecryptPermission(c, cph.KeyVersion); err != nil {
		return nil, err
	}
	if err := s.checkTargetPermission(c, targetVersion); err != nil {
		return nil, err
	}
	return s.codec.ReWrap(cph, targetVersion)
}

// checkTargetPermission 判定调用方是否有权以指定版本作为加密/换保目标。
// 空授权集仅允许当前活跃版本；显式授权集须包含目标版本。
// 目标版本本身必须 ENABLED，由 kms 层在包装时强制校验。
func (s *Service) checkTargetPermission(c Caller, targetVersion string) error {
	active, err := s.store.ActiveVersion()
	activeID := ""
	if err == nil {
		activeID = active.ID
	}
	if !c.allows(targetVersion, activeID) {
		return fmt.Errorf("%w: caller %q may not use version %q as migration target",
			ErrPermissionDenied, c.Domain, targetVersion)
	}
	return nil
}

// MigrateBatch 批量换保：逐项独立迁移，单项失败不影响其他项，
// 返回与输入等长的结果切片（按输入顺序对应）。
// 整个批次可在轮换、并发写入进行中安全调用；失败项可取出原密文重试，
// 重试不会重复生效或造成错乱（ReWrap 幂等、原密文不被修改）。
func (s *Service) MigrateBatch(c Caller, ciphers []*envelope.Cipher, targetVersion string) []MigrationResult {
	results := make([]MigrationResult, len(ciphers))
	for i, cph := range ciphers {
		migrated, err := s.Migrate(c, cph, targetVersion)
		if err != nil {
			results[i].Err = err
			continue
		}
		results[i].Cipher = migrated
	}
	return results
}
