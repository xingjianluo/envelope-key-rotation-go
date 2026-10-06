package service

import (
	"errors"
	"fmt"

	"github.com/xingjianluo/envelope-key-rotation-go/envelope"
)

// ErrUnknownRecord 表示待迁移的密文记录不存在。
var ErrUnknownRecord = errors.New("service: unknown cipher record")

// MigrateResult 是单条记录的迁移结论。
type MigrateResult struct {
	ID          string
	FromVersion string // 迁移前密文记录的版本（记录不存在时为空）
	ToVersion   string // 迁移后密文记录的版本（失败时为空）
	Migrated    bool   // false 表示幂等命中（已在目标版本，未重复生效）
	Err         error  // 非 nil 表示本条失败，记录保持原值，可重试
}

// Migrate 将单条记录从旧保护版本迁移到 targetVersion。
//
// 原子性：整个"读旧密文 → 换保 → 替换记录"在记录级临界区内完成，
// 要么全部生效，要么保持原值，不存在半迁移状态。
// 幂等：记录已在目标版本时直接成功（Migrated=false），重试不会重复生效。
// 失败安全：源版本已销毁、目标版本停用/销毁等错误都会使记录保持原值，
// 修正条件后重试即可。
func (s *Service) Migrate(id, targetVersion string) MigrateResult {
	res := MigrateResult{ID: id}
	err := s.records.Update(id, func(cur *envelope.Cipher, ok bool) (*envelope.Cipher, error) {
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownRecord, id)
		}
		res.FromVersion = cur.KeyVersion
		if cur.KeyVersion == targetVersion {
			res.ToVersion = cur.KeyVersion
			return cur, nil // 幂等：已在目标版本
		}
		migrated, err := s.codec.ReWrap(cur, targetVersion)
		if err != nil {
			return nil, err // 记录保持原值
		}
		res.ToVersion = migrated.KeyVersion
		res.Migrated = true
		return migrated, nil
	})
	res.Err = err
	return res
}

// MigrateBatch 批量迁移：逐条独立结算，单条失败不影响其他记录，
// 也不中断批次；返回与 ids 等长、顺序一致的结果切片，
// 调用方可据 Err 字段挑出失败项重试。
func (s *Service) MigrateBatch(ids []string, targetVersion string) []MigrateResult {
	results := make([]MigrateResult, len(ids))
	for i, id := range ids {
		results[i] = s.Migrate(id, targetVersion)
	}
	return results
}
