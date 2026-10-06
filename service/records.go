package service

import (
	"sync"

	"github.com/xingjianluo/envelope-key-rotation-go/envelope"
)

// RecordStore 是密文记录的内存存储。迁移以单条记录为原子单位：
// 对同一记录的读-改-写在记录级临界区内完成，不存在"迁移到一半"的中间态；
// 不同记录之间互不阻塞，可与轮换、并发写入同时进行。
type RecordStore struct {
	mu      sync.RWMutex
	records map[string]*envelope.Cipher
}

// NewRecordStore 创建空记录存储。
func NewRecordStore() *RecordStore {
	return &RecordStore{records: make(map[string]*envelope.Cipher)}
}

// Put 写入（或覆盖）一条密文记录。存储持有的是传入指针，
// 调用方不应再原地修改该 Cipher。
func (s *RecordStore) Put(id string, cph *envelope.Cipher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[id] = cph
}

// Get 读取一条密文记录。
func (s *RecordStore) Get(id string) (*envelope.Cipher, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cph, ok := s.records[id]
	return cph, ok
}

// Update 在单把写锁保护的临界区内用 fn 计算新值并原子替换：
// fn 返回错误时记录保持原值（失败安全、可重试）；
// fn 返回原值时是幂等空操作。
func (s *RecordStore) Update(id string, fn func(cur *envelope.Cipher, ok bool) (*envelope.Cipher, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.records[id]
	next, err := fn(cur, ok)
	if err != nil {
		return err
	}
	s.records[id] = next
	return nil
}
