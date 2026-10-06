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
	dek := make([]byte, 32) // AES-256 数据密钥
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	wrapped, err := c.store.Wrap(active.ID, dek)
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
		KeyVersion: active.ID,
		WrappedDEK: wrapped,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(active.ID)),
	}, nil
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

// ReWrap 把密文从当前记录版本迁移（换保）到 targetVersion 保护：
// 用旧版本解包 DEK、用目标版本重新包装，并用同一 DEK 以新 AAD 重封明文。
//
// 语义保证：
//   - 原密文不被修改，任何一步失败都返回错误且原密文仍可解；
//   - 成功返回的新密文解出的明文与原密文逐字节一致；
//   - 目标版本必须 ENABLED（停用/销毁版本由 kms 层拒绝，见 ErrVersionDisabled 等）；
//   - 源版本必须仍可解包（ENABLED/DISABLED），已销毁则报 ErrVersionDestroyed；
//   - 幂等：对同一份原密文重复调用均成功且结果等价，可安全重试。
func (c *Codec) ReWrap(cph *Cipher, targetVersion string) (*Cipher, error) {
	if cph == nil {
		return nil, fmt.Errorf("envelope: nil cipher")
	}
	if targetVersion == "" {
		return nil, fmt.Errorf("envelope: target version must not be empty")
	}
	// 先解包 DEK（校验源版本可解），再解出明文以验证完整性。
	dek, err := c.store.Unwrap(cph.KeyVersion, cph.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: init DEK GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, cph.Nonce, cph.Ciphertext, []byte(cph.KeyVersion))
	if err != nil {
		return nil, fmt.Errorf("envelope: verify source cipher: %w", err)
	}
	// 用目标版本重新包装同一 DEK；目标版本非 ENABLED 时在此被拒绝。
	wrapped, err := c.store.Wrap(targetVersion, dek)
	if err != nil {
		return nil, err
	}
	// 用新随机数重封明文，AAD 绑定目标版本。
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope: rewrap nonce: %w", err)
	}
	return &Cipher{
		KeyVersion: targetVersion,
		WrappedDEK: wrapped,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(targetVersion)),
	}, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
