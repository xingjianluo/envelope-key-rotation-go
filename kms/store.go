package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// Store 是本地密钥存储，模拟 KMS 后端。所有方法并发安全。
//
// 并发语义：所有读写经单一 RWMutex 串行化，轮换（Rotate）在持锁状态下
// 完成"创建新版本 + 切换活跃指针"，对外不存在部分更新的中间态。
type Store struct {
	mu       sync.RWMutex
	versions map[string]*MasterKeyVersion
	activeID string
	seq      int64
	// activated 记录所有曾经成为活跃版本的 ID（含当前活跃版本）。
	// 用于判定"普通调用方在版本活跃期间合法写入的密文"，
	// 版本一旦活跃过即永久在册，不随停用/销毁移除。
	activated map[string]bool
}

// NewStore 创建空密钥存储。
func NewStore() *Store {
	return &Store{
		versions:  make(map[string]*MasterKeyVersion),
		activated: make(map[string]bool),
	}
}

// CreateVersion 创建新的主密钥版本并返回。密钥材料随机生成，不对外暴露。
func (s *Store) CreateVersion(id string) (*MasterKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createVersionLocked(id)
}

func (s *Store) createVersionLocked(id string) (*MasterKeyVersion, error) {
	if id == "" {
		return nil, fmt.Errorf("kms: version id must not be empty")
	}
	if _, ok := s.versions[id]; ok {
		return nil, fmt.Errorf("kms: version %q already exists", id)
	}
	material := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return nil, fmt.Errorf("kms: generate key material: %w", err)
	}
	s.seq++
	v := &MasterKeyVersion{ID: id, State: StateEnabled, Created: s.seq, material: material}
	s.versions[id] = v
	if s.activeID == "" {
		s.activeID = id
		s.activated[id] = true
	}
	return v, nil
}

// ActiveVersion 返回当前用于加密的活跃版本。
func (s *Store) ActiveVersion() (*MasterKeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeID == "" {
		return nil, ErrNoActiveVersion
	}
	v := s.versions[s.activeID]
	if v == nil || v.State != StateEnabled {
		return nil, ErrNoActiveVersion
	}
	return v, nil
}

// Get 返回指定版本。
func (s *Store) Get(id string) (*MasterKeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.versions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownVersion, id)
	}
	return v, nil
}

// Disable 停用指定版本：不再可用于加密，仍可解密。
// 若停用的是活跃版本，活跃指针回退到最近创建的 ENABLED 版本。
func (s *Store) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownVersion, id)
	}
	if v.State == StateDestroyed {
		return fmt.Errorf("%w: %q", ErrVersionDestroyed, id)
	}
	v.State = StateDisabled
	if s.activeID == id {
		s.setActiveLocked(s.latestEnabledLocked())
	}
	return nil
}

// Destroy 销毁指定版本（不可逆）：密钥材料被清零，历史数据不可再解。
func (s *Store) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownVersion, id)
	}
	if v.State == StateDestroyed {
		return fmt.Errorf("%w: %q", ErrAlreadyDestroyed, id)
	}
	v.State = StateDestroyed
	for i := range v.material {
		v.material[i] = 0
	}
	v.material = nil
	if s.activeID == id {
		s.setActiveLocked(s.latestEnabledLocked())
	}
	return nil
}

func (s *Store) latestEnabledLocked() string {
	best := ""
	var bestSeq int64
	for id, v := range s.versions {
		if v.State == StateEnabled && (best == "" || v.Created > bestSeq) {
			best, bestSeq = id, v.Created
		}
	}
	return best
}

// Rotate 原子地创建新版本并切换活跃指针。
// fn 在切换前、持锁状态下执行；fn 返回错误则删除新版本并回滚，
// 既有版本与活跃指针保持不变。
func (s *Store) Rotate(newID string, fn func(newVersion *MasterKeyVersion) error) (*MasterKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.createVersionLocked(newID)
	if err != nil {
		return nil, err
	}
	if fn != nil {
		if err := fn(v); err != nil {
			delete(s.versions, newID) // 回滚：撤销新版本
			return nil, err
		}
	}
	s.setActiveLocked(newID)
	return v, nil
}

// setActiveLocked 切换活跃指针，并把新活跃版本记入"曾活跃"名册。
func (s *Store) setActiveLocked(id string) {
	s.activeID = id
	if id != "" {
		s.activated[id] = true
	}
}

// WasActive 报告版本是否曾经（或正在）担任活跃版本。
// 用于读取兼容判定：普通调用方在版本活跃期间写入的密文，
// 轮换后仍应可解，不因活跃指针前移而被判越权。
func (s *Store) WasActive(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activated[id]
}

// Wrap 用指定版本包装数据密钥，不暴露主密钥材料。
// 仅 ENABLED 版本可用于包装（加密方向）。
func (s *Store) Wrap(versionID string, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, err := s.usableLocked(versionID, true)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms: wrap nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(versionID)), nil
}

// Unwrap 用指定版本解包数据密钥。
// ENABLED 与 DISABLED 版本可解包（解密方向），DESTROYED 不可。
func (s *Store) Unwrap(versionID string, wrapped []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, err := s.usableLocked(versionID, false)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(v)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, fmt.Errorf("kms: wrapped key too short")
	}
	nonce, ct := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, []byte(versionID))
}

// usableLocked 校验版本存在性与状态，forEncrypt 区分加密/解密方向。
func (s *Store) usableLocked(id string, forEncrypt bool) (*MasterKeyVersion, error) {
	v, ok := s.versions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownVersion, id)
	}
	switch v.State {
	case StateDestroyed:
		return nil, fmt.Errorf("%w: %q", ErrVersionDestroyed, id)
	case StateDisabled:
		if forEncrypt {
			return nil, fmt.Errorf("%w: %q", ErrVersionDisabled, id)
		}
	}
	return v, nil
}

func gcmFor(v *MasterKeyVersion) (cipher.AEAD, error) {
	block, err := aes.NewCipher(v.material)
	if err != nil {
		return nil, fmt.Errorf("kms: init cipher for %q: %w", v.ID, err)
	}
	return cipher.NewGCM(block)
}

// Versions 返回全部版本的快照（不含密钥材料）。
func (s *Store) Versions() []MasterKeyVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MasterKeyVersion, 0, len(s.versions))
	for _, v := range s.versions {
		out = append(out, MasterKeyVersion{ID: v.ID, State: v.State, Created: v.Created})
	}
	return out
}
