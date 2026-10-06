// Package envelope 实现信封加密：数据密钥保护明文，主密钥版本包装数据密钥。
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/xingjianluo/envelope-key-rotation-go/kms"
)

// Cipher 是信封格式的密文，记录所用主密钥版本。
type Cipher struct {
	KeyVersion string // 包装数据密钥所用的主密钥版本
	WrappedDEK []byte // 被主密钥包装的数据密钥
	Nonce      []byte // 数据加密随机数
	Ciphertext []byte // AES-GCM 密文
}

// Codec 基于密钥存储提供信封加解密。主密钥材料永不离开 kms.Store。
type Codec struct {
	store *kms.Store
}

// NewCodec 创建信封编解码器。
func NewCodec(store *kms.Store) *Codec { return &Codec{store: store} }

// Encrypt 用当前活跃主密钥版本加密明文：
// 1. 取活跃版本；2. 生成随机 DEK；3. 用该版本包装 DEK；4. 用 DEK 加密明文。
func (c *Codec) Encrypt(plaintext []byte) (*Cipher, error) {
	active, err := c.store.ActiveVersion()
	if err != nil {
		return nil, err
	}
	return c.encryptWith(active.ID, plaintext)
}

// encryptWith 用指定版本加密明文。Wrap 会强制版本为 ENABLED，
// 因此停用/销毁版本从任何路径都无法参与加密。
func (c *Codec) encryptWith(versionID string, plaintext []byte) (*Cipher, error) {
	dek := make([]byte, 32) // AES-256 数据密钥
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	wrapped, err := c.store.Wrap(versionID, dek)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope: nonce: %w", err)
	}
	return &Cipher{
		KeyVersion: versionID,
		WrappedDEK: wrapped,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(versionID)),
	}, nil
}

// ReWrap 将密文从当前记录版本迁移到 targetVersion（换保）：
// 解出明文后在目标版本下重新加密，明文逐字节不变，改由目标版本保护。
//
// 语义：
//   - 幂等：密文已在目标版本时原样返回，不重复生效；
//   - 失败安全：任何一步失败都返回错误，原密文不被修改，可安全重试；
//   - 硬约束：目标版本必须 ENABLED（由 Wrap 强制），停用/销毁版本
//     无法作为迁移目标；源版本为 DESTROYED 时返回 ErrVersionDestroyed。
func (c *Codec) ReWrap(cph *Cipher, targetVersion string) (*Cipher, error) {
	if cph == nil {
		return nil, fmt.Errorf("envelope: nil cipher")
	}
	if targetVersion == "" {
		return nil, fmt.Errorf("envelope: target version must not be empty")
	}
	if cph.KeyVersion == targetVersion {
		return cph, nil // 幂等：已在目标版本
	}
	plaintext, err := c.Decrypt(cph) // 用源版本解出明文（源版本须可解）
	if err != nil {
		return nil, err
	}
	return c.encryptWith(targetVersion, plaintext)
}

// Decrypt 依据密文记录的密钥版本解密：
// 未知版本、已销毁版本会被 kms 层以可区分错误拒绝。
func (c *Codec) Decrypt(cph *Cipher) ([]byte, error) {
	if cph == nil {
		return nil, fmt.Errorf("envelope: nil cipher")
	}
	dek, err := c.store.Unwrap(cph.KeyVersion, cph.WrappedDEK)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK GCM: %w", err)
	}
	return gcm.Open(nil, cph.Nonce, cph.Ciphertext, []byte(cph.KeyVersion))
}
