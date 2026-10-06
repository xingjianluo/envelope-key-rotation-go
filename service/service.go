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
	// AllowedVersions 为允许使用的版本集合；为空表示普通调用方：
	// 加密跟随当前活跃版本，解密兼容所有当前仍可解的历史版本。
	AllowedVersions map[string]bool
}

// allows 判定加密方向的版本权限：空授权集仅允许活跃版本，
// 非空授权集要求显式包含目标版本。
func (c Caller) allows(versionID string, activeID string) bool {
	if c.AllowedVersions == nil {
		return versionID == activeID
	}
	return c.AllowedVersions[versionID]
}

// Service 是信封加密与轮换服务入口。
type Service struct {
	store   *kms.Store
	codec   *envelope.Codec
	records *RecordStore
}

// New 创建服务。
func New(store *kms.Store, codec *envelope.Codec) *Service {
	return &Service{store: store, codec: codec, records: NewRecordStore()}
}

// Records 返回服务持有的密文记录存储。
func (s *Service) Records() *RecordStore { return s.records }

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

// Decrypt 以调用方权限解密：按密文记录的版本选择主密钥。
//
// 兼容语义：未做逐版本授权（AllowedVersions 为空）的普通调用方，
// 可解密任何"当前仍可解"的版本（ENABLED/DISABLED）——轮换只改变版本号，
// 不构成越权；版本已销毁或不存在时，由 kms 层返回可区分的版本错误
// （ErrVersionDestroyed / ErrUnknownVersion），而非权限错误。
// 显式授权集（AllowedVersions 非空）仍逐版本强制：不在集合内即
// ErrPermissionDenied，与版本失效错误泾渭分明。
func (s *Service) Decrypt(c Caller, cph *envelope.Cipher) ([]byte, error) {
	if cph == nil {
		return nil, fmt.Errorf("service: nil cipher")
	}
	if c.AllowedVersions != nil && !c.AllowedVersions[cph.KeyVersion] {
		return nil, fmt.Errorf("%w: caller %q may not decrypt with version %q",
			ErrPermissionDenied, c.Domain, cph.KeyVersion)
	}
	return s.codec.Decrypt(cph)
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
