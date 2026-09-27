package kms

import (
	"errors"
	"testing"
)

func TestVersionLifecycle(t *testing.T) {
	s := NewStore()
	if _, err := s.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if _, err := s.CreateVersion("v2"); err != nil {
		t.Fatalf("create v2: %v", err)
	}

	// 活跃版本应为首个创建的版本 v1。
	active, err := s.ActiveVersion()
	if err != nil || active.ID != "v1" {
		t.Fatalf("active = %v, %v; want v1", active, err)
	}
	t.Logf("判定依据: 首个创建版本成为活跃版本, active=%s", active.ID)

	// 未知版本：Wrap/Unwrap 均报 ErrUnknownVersion。
	if _, err := s.Wrap("nope", []byte("k")); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("wrap unknown: %v; want ErrUnknownVersion", err)
	}
	t.Logf("判定依据: 版本 nope 不存在 -> ErrUnknownVersion")

	// 停用 v1：不可再 Wrap，但仍可 Unwrap。
	wrapped, err := s.Wrap("v1", []byte("dek"))
	if err != nil {
		t.Fatalf("wrap v1: %v", err)
	}
	if err := s.Disable("v1"); err != nil {
		t.Fatalf("disable v1: %v", err)
	}
	if _, err := s.Wrap("v1", []byte("k")); !errors.Is(err, ErrVersionDisabled) {
		t.Fatalf("wrap disabled: %v; want ErrVersionDisabled", err)
	}
	if _, err := s.Unwrap("v1", wrapped); err != nil {
		t.Fatalf("unwrap disabled should still work: %v", err)
	}
	t.Logf("判定依据: v1 DISABLED -> 加密拒绝(ErrVersionDisabled), 解密放行")

	// 销毁 v1：Unwrap 也拒绝，且不可逆。
	if err := s.Destroy("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, err := s.Unwrap("v1", wrapped); !errors.Is(err, ErrVersionDestroyed) {
		t.Fatalf("unwrap destroyed: %v; want ErrVersionDestroyed", err)
	}
	if err := s.Destroy("v1"); !errors.Is(err, ErrAlreadyDestroyed) {
		t.Fatalf("re-destroy: %v; want ErrAlreadyDestroyed", err)
	}
	t.Logf("判定依据: v1 DESTROYED -> 解密拒绝(ErrVersionDestroyed), 重复销毁拒绝(ErrAlreadyDestroyed)")
}

func TestRotateRollback(t *testing.T) {
	s := NewStore()
	if _, err := s.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	boom := errors.New("injected failure")
	_, err := s.Rotate("v2", func(_ *MasterKeyVersion) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("rotate err = %v; want injected failure", err)
	}
	// 回滚后：v2 不存在，活跃版本仍是 v1。
	if _, err := s.Get("v2"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("v2 after rollback: %v; want ErrUnknownVersion", err)
	}
	active, _ := s.ActiveVersion()
	if active.ID != "v1" {
		t.Fatalf("active after rollback = %s; want v1", active.ID)
	}
	t.Logf("判定依据: 轮换失败 -> 新版本 v2 被撤销, 活跃版本保持 %s", active.ID)
}
