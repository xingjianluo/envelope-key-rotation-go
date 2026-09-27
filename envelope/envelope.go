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
