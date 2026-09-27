// Package envelope 在 keystore 之上提供信封加密服务。
// 明文由一次性数据密钥（DEK）保护，DEK 由主密钥版本包装。
// 主密钥材料从不离开 keystore，本包只接触 DEK。
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/xingjianluo/envelope-key-rotation-go/internal/keystore"
)

// 信封密文格式（二进制，大端序）：
//
//	magic(4) | wireVer(1) | keyVersion(4) | wrappedDEKLen(2) | wrappedDEK | nonce(12) | ciphertext
//
// keyVersion 记录加密时所用的主密钥版本，解密时据此选择主密钥。
const (
	magic        = "EKR1"
	wireVer      = 1
	headerLen    = 4 + 1 + 4 + 2
	gcmNonceSize = 12
	dekSize      = 32
)

// 信封层可区分的错误原因（密钥相关错误由 keystore 透传）。
var (
	ErrMalformedEnvelope = errors.New("envelope: malformed ciphertext")
	ErrUnsupportedWire   = errors.New("envelope: unsupported wire version")
	ErrDecryptFailed     = errors.New("envelope: ciphertext authentication failed")
)

// Envelope 是编码后的信封密文。
type Envelope struct {
	KeyVersion int    // 加密时使用的主密钥版本
	Bytes      []byte // 完整编码后的信封字节
}

// Service 提供信封加解密。每个 Service 绑定一个调用方身份（权限域）。
type Service struct {
	store  *keystore.Store
	caller string
}

// NewService 创建绑定指定调用方身份的信封服务。
func NewService(store *keystore.Store, caller string) *Service {
	return &Service{store: store, caller: caller}
}

// Caller 返回本服务绑定的调用方身份。
func (s *Service) Caller() string { return s.caller }

// Encrypt 用当前主密钥版本加密明文，返回信封密文。
// 流程：原子地取当前版本并包装一次性 DEK -> DEK 加密明文 -> 清零 DEK。
// "取版本+包装"在 keystore 内原子完成，并发轮换下不会暴露中间态。
func (s *Service) Encrypt(plaintext []byte) (*Envelope, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer zero(dek)

	version, wrapped, err := s.store.WrapCurrent(s.caller, dek)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	buf := make([]byte, 0, headerLen+len(wrapped)+len(nonce)+len(ciphertext))
	buf = append(buf, magic...)
	buf = append(buf, wireVer)
	buf = binary.BigEndian.AppendUint32(buf, uint32(version))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(wrapped)))
	buf = append(buf, wrapped...)
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)
	return &Envelope{KeyVersion: version, Bytes: buf}, nil
}

// Decrypt 依据信封中记录的密钥版本解密。
// 未知版本、已销毁版本、越权访问分别返回可区分的错误（由 keystore 透传）。
func (s *Service) Decrypt(env *Envelope) ([]byte, error) {
	keyVersion, wrapped, nonce, ciphertext, err := split(env.Bytes)
	if err != nil {
		return nil, err
	}
	dek, err := s.store.Unwrap(s.caller, keyVersion, wrapped)
	if err != nil {
		return nil, err
	}
	defer zero(dek)

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w (key version %d)", ErrDecryptFailed, keyVersion)
	}
	return plaintext, nil
}

// Parse 解码信封字节，返回其记录的密钥版本等信息（不解密）。
func Parse(data []byte) (*Envelope, error) {
	keyVersion, _, _, _, err := split(data)
	if err != nil {
		return nil, err
	}
	return &Envelope{KeyVersion: keyVersion, Bytes: data}, nil
}

// split 按线格式拆解信封字节。
func split(data []byte) (keyVersion int, wrapped, nonce, ciphertext []byte, err error) {
	if len(data) < headerLen {
		return 0, nil, nil, nil, fmt.Errorf("%w: too short (%d bytes)", ErrMalformedEnvelope, len(data))
	}
	if string(data[:4]) != magic {
		return 0, nil, nil, nil, fmt.Errorf("%w: bad magic", ErrMalformedEnvelope)
	}
	if data[4] != wireVer {
		return 0, nil, nil, nil, fmt.Errorf("%w: %d", ErrUnsupportedWire, data[4])
	}
	keyVersion = int(binary.BigEndian.Uint32(data[5:9]))
	wrappedLen := int(binary.BigEndian.Uint16(data[9:11]))
	rest := data[headerLen:]
	if len(rest) < wrappedLen+gcmNonceSize {
		return 0, nil, nil, nil, fmt.Errorf("%w: truncated wrapped key or nonce", ErrMalformedEnvelope)
	}
	wrapped = rest[:wrappedLen]
	nonce = rest[wrappedLen : wrappedLen+gcmNonceSize]
	ciphertext = rest[wrappedLen+gcmNonceSize:]
	return keyVersion, wrapped, nonce, ciphertext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: init cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
