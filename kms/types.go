// Package kms 提供本地密钥存储，模拟密钥管理后端（KMS）。
package kms

import "errors"

// VersionState 表示主密钥版本的生命周期状态。
type VersionState int

const (
	// StateEnabled 版本可用：可用于加密与解密。
	StateEnabled VersionState = iota
	// StateDisabled 版本停用：不可用于加密，仍可用于解密。
	StateDisabled
	// StateDestroyed 版本销毁：不可逆，加解密均不可用。
	StateDestroyed
)

func (s VersionState) String() string {
	switch s {
	case StateEnabled:
		return "ENABLED"
	case StateDisabled:
		return "DISABLED"
	case StateDestroyed:
		return "DESTROYED"
	default:
		return "UNKNOWN"
	}
}

// 可区分的错误原因，调用方可用 errors.Is 判定。
var (
	ErrUnknownVersion   = errors.New("kms: unknown key version")
	ErrVersionDisabled  = errors.New("kms: key version disabled")
	ErrVersionDestroyed = errors.New("kms: key version destroyed")
	ErrNoActiveVersion  = errors.New("kms: no active key version")
	ErrAlreadyDestroyed = errors.New("kms: key version already destroyed")
)

// MasterKeyVersion 是一个主密钥版本。密钥材料不对外暴露。
type MasterKeyVersion struct {
	ID       string
	State    VersionState
	Created  int64 // 逻辑序号，用于排序
	material []byte
}
