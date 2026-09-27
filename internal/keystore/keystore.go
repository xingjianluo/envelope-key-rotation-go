// Package keystore 以本地密钥存储模拟密钥管理后端（KMS）。
// 主密钥材料永不离开本包，对外仅提供 Wrap/Unwrap 能力。
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// VersionState 表示密钥版本的生命周期状态。
type VersionState int

const (
	StateEnabled   VersionState = iota // 可用于加密与解密
	StateDisabled                      // 仅可用于解密，不可用于加密
	StateDestroyed                     // 已销毁，加解密均不可用（不可逆）
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

// 可区分的错误原因。
var (
	ErrUnknownVersion   = errors.New("keystore: unknown key version")
	ErrVersionDisabled  = errors.New("keystore: key version disabled")
	ErrVersionDestroyed = errors.New("keystore: key version destroyed")
	ErrPermissionDenied = errors.New("keystore: permission denied")
	ErrNoActiveVersion  = errors.New("keystore: no active key version")
	ErrInvalidState     = errors.New("keystore: invalid state transition")
)

// VersionInfo 是密钥版本的对外可见元信息（不含密钥材料）。
type VersionInfo struct {
	ID    int
	State VersionState
}

// keyVersion 为内部版本记录，material 永不导出。
type keyVersion struct {
	info     VersionInfo
	material []byte // 32 字节 AES-256 主密钥
}

// Store 是本地密钥存储，模拟 KMS 后端。所有方法并发安全。
type Store struct {
	mu         sync.RWMutex
	versions   map[int]*keyVersion
	current    int                     // 当前用于加密的版本；0 表示尚未创建
	nextID     int                     // 下一个版本号（从 1 开始）
	grants     map[string]map[int]bool // caller -> version -> allowed
	rotateHook func() error            // 测试钩子：在轮换提交前注入失败
}

// New 创建空的密钥存储。
func New() *Store {
	return &Store{
		versions: make(map[int]*keyVersion),
		grants:   make(map[string]map[int]bool),
	}
}

// SetRotateHook 设置轮换钩子（仅用于测试）：在提交前调用，返回错误则整体回滚。
func (s *Store) SetRotateHook(h func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateHook = h
}

// CreateVersion 生成一个新版本并设为当前版本，返回版本号。
func (s *Store) CreateVersion() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createVersionLocked()
}

func (s *Store) createVersionLocked() (int, error) {
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		return 0, fmt.Errorf("keystore: generate key material: %w", err)
	}
	s.nextID++
	id := s.nextID
	s.versions[id] = &keyVersion{
		info:     VersionInfo{ID: id, State: StateEnabled},
		material: material,
	}
	s.current = id
	return id, nil
}

// CurrentVersion 返回当前用于加密的版本号。
func (s *Store) CurrentVersion() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == 0 {
		return 0, ErrNoActiveVersion
	}
	v := s.versions[s.current]
	if v.info.State != StateEnabled {
		return 0, ErrNoActiveVersion
	}
	return s.current, nil
}

// Info 返回指定版本的元信息。
func (s *Store) Info(id int) (VersionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.versions[id]
	if !ok {
		return VersionInfo{}, ErrUnknownVersion
	}
	return v.info, nil
}

// Versions 返回全部版本的元信息快照。
func (s *Store) Versions() []VersionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]VersionInfo, 0, len(s.versions))
	for _, v := range s.versions {
		out = append(out, v.info)
	}
	return out
}

// checkLocked 校验版本存在性与调用方权限，返回版本记录。
func (s *Store) checkLocked(caller string, version int) (*keyVersion, error) {
	v, ok := s.versions[version]
	if !ok {
		return nil, ErrUnknownVersion
	}
	if !s.grants[caller][version] {
		return nil, fmt.Errorf("%w: caller %q has no grant on version %d", ErrPermissionDenied, caller, version)
	}
	return v, nil
}

// WrapCurrent 原子地完成"读取当前版本 + 校验 + 包装"，
// 保证并发轮换下不会看到中间态：返回的密文一定由返回的版本包装。
func (s *Store) WrapCurrent(caller string, plaintext []byte) (int, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == 0 {
		return 0, nil, ErrNoActiveVersion
	}
	v := s.versions[s.current]
	if v.info.State != StateEnabled {
		return 0, nil, ErrNoActiveVersion
	}
	if !s.grants[caller][s.current] {
		return 0, nil, fmt.Errorf("%w: caller %q has no grant on version %d", ErrPermissionDenied, caller, s.current)
	}
	wrapped, err := seal(v.material, plaintext)
	if err != nil {
		return 0, nil, err
	}
	return s.current, wrapped, nil
}

// Wrap 用指定版本的主密钥包装数据密钥。调用方须对该版本有权限且版本为 Enabled。
// 输出为 nonce || AES-GCM(plaintext)，主密钥材料不出本包。
func (s *Store) Wrap(caller string, version int, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, err := s.checkLocked(caller, version)
	if err != nil {
		return nil, err
	}
	switch v.info.State {
	case StateDisabled:
		return nil, fmt.Errorf("%w: version %d cannot encrypt", ErrVersionDisabled, version)
	case StateDestroyed:
		return nil, fmt.Errorf("%w: version %d cannot encrypt", ErrVersionDestroyed, version)
	}
	return seal(v.material, plaintext)
}

// Unwrap 用指定版本的主密钥解包数据密钥。Enabled/Disabled 版本可用，Destroyed 拒绝。
func (s *Store) Unwrap(caller string, version int, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, err := s.checkLocked(caller, version)
	if err != nil {
		return nil, err
	}
	if v.info.State == StateDestroyed {
		return nil, fmt.Errorf("%w: version %d cannot decrypt", ErrVersionDestroyed, version)
	}
	return open(v.material, ciphertext)
}

// Rotate 原子地轮换主密钥：生成新版本并切换当前版本。
// 新版本的授权继承自旧当前版本。中途失败（钩子注入）时整体回滚：
// 删除待提交的新版本，当前版本与既有版本保持不变。
func (s *Store) Rotate() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldCurrent := s.current
	newID, err := s.createVersionLocked()
	if err != nil {
		return 0, err
	}
	// 继承旧当前版本的授权，保证轮换后被授权调用方连续可用。
	if oldCurrent != 0 {
		for _, set := range s.grants {
			if set[oldCurrent] {
				set[newID] = true
			}
		}
	}
	// 提交点之前允许注入失败；失败则回滚：删除新版本、恢复授权与当前版本。
	if s.rotateHook != nil {
		if err := s.rotateHook(); err != nil {
			delete(s.versions, newID)
			for _, set := range s.grants {
				delete(set, newID)
			}
			s.nextID--
			s.current = oldCurrent
			return 0, fmt.Errorf("keystore: rotation rolled back: %w", err)
		}
	}
	// 提交：旧版本停用（仍可解密），新版本成为当前版本。
	if oldCurrent != 0 {
		s.versions[oldCurrent].info.State = StateDisabled
	}
	s.current = newID
	return newID, nil
}

// Disable 停用指定版本：不再允许加密，仍允许解密。
func (s *Store) Disable(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return ErrUnknownVersion
	}
	switch v.info.State {
	case StateDisabled:
		return nil // 幂等
	case StateDestroyed:
		return fmt.Errorf("%w: version %d already destroyed", ErrInvalidState, id)
	}
	v.info.State = StateDisabled
	return nil
}

// Destroy 销毁指定版本：不可逆，之后加解密均拒绝，密钥材料被清零。
func (s *Store) Destroy(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return ErrUnknownVersion
	}
	if v.info.State == StateDestroyed {
		return fmt.Errorf("%w: version %d already destroyed", ErrInvalidState, id)
	}
	for i := range v.material {
		v.material[i] = 0
	}
	v.material = nil
	v.info.State = StateDestroyed
	return nil
}

// Grant 授权调用方使用指定版本。
func (s *Store) Grant(caller string, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[id]; !ok {
		return ErrUnknownVersion
	}
	if s.grants[caller] == nil {
		s.grants[caller] = make(map[int]bool)
	}
	s.grants[caller][id] = true
	return nil
}

// Revoke 撤销调用方对指定版本的授权。
func (s *Store) Revoke(caller string, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[id]; !ok {
		return ErrUnknownVersion
	}
	delete(s.grants[caller], id)
	return nil
}

// seal 用主密钥做 AES-256-GCM 加密，输出 nonce || ciphertext。
func seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// open 是 seal 的逆操作。
func open(key, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("keystore: malformed wrapped key")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: init cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
