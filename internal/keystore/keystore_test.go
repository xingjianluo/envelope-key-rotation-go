package keystore

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// newGrantedStore 创建存储、初始版本并授权调用方。
func newGrantedStore(t *testing.T, callers ...string) (*Store, int) {
	t.Helper()
	s := New()
	v, err := s.CreateVersion()
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	for _, c := range callers {
		if err := s.Grant(c, v); err != nil {
			t.Fatalf("Grant(%q, v%d): %v", c, v, err)
		}
	}
	return s, v
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	s, v := newGrantedStore(t, "alice")
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := s.Wrap("alice", v, dek)
	if err != nil {
		t.Fatalf("Wrap v%d: %v", v, err)
	}
	got, err := s.Unwrap("alice", v, wrapped)
	if err != nil {
		t.Fatalf("Unwrap v%d: %v", v, err)
	}
	if string(got) != string(dek) {
		t.Fatalf("round trip mismatch on v%d", v)
	}
	t.Logf("v%d: Wrap/Unwrap 往返一致", v)
}

func TestUnknownVersionRejected(t *testing.T) {
	s, _ := newGrantedStore(t, "alice")
	_, err := s.Unwrap("alice", 999, []byte("x"))
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
	t.Logf("v999: 未知版本被拒绝，原因=%v", err)
}

func TestDisableThenEncryptRejectedDecryptAllowed(t *testing.T) {
	s, v := newGrantedStore(t, "alice")
	dek := []byte("dek-material-for-disable-test!")
	wrapped, err := s.Wrap("alice", v, dek)
	if err != nil {
		t.Fatalf("Wrap v%d: %v", v, err)
	}
	if err := s.Disable(v); err != nil {
		t.Fatalf("Disable v%d: %v", v, err)
	}
	if _, err := s.Wrap("alice", v, dek); !errors.Is(err, ErrVersionDisabled) {
		t.Fatalf("want ErrVersionDisabled on encrypt, got %v", err)
	}
	t.Logf("v%d 停用后: 加密被拒绝，原因=ErrVersionDisabled", v)
	got, err := s.Unwrap("alice", v, wrapped)
	if err != nil || string(got) != string(dek) {
		t.Fatalf("disabled v%d must still decrypt: got=%v err=%v", v, got, err)
	}
	t.Logf("v%d 停用后: 既有密文仍可解密（判定依据：DISABLED 仅禁止加密）", v)
}

func TestDestroyIrreversibleAndUndecryptable(t *testing.T) {
	s, v := newGrantedStore(t, "alice")
	dek := []byte("dek-material-for-destroy-test!")
	wrapped, err := s.Wrap("alice", v, dek)
	if err != nil {
		t.Fatalf("Wrap v%d: %v", v, err)
	}
	if err := s.Destroy(v); err != nil {
		t.Fatalf("Destroy v%d: %v", v, err)
	}
	if _, err := s.Unwrap("alice", v, wrapped); !errors.Is(err, ErrVersionDestroyed) {
		t.Fatalf("want ErrVersionDestroyed on decrypt, got %v", err)
	}
	t.Logf("v%d 销毁后: 解密被拒绝，原因=ErrVersionDestroyed（历史数据按策略不再可解）", v)
	if err := s.Disable(v); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("destroyed version must reject Disable, got %v", err)
	}
	if err := s.Destroy(v); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("destroy must be irreversible, got %v", err)
	}
	t.Logf("v%d 销毁后: 再次 Disable/Destroy 均返回 ErrInvalidState（不可逆）", v)
}

func TestPermissionDenied(t *testing.T) {
	s, v := newGrantedStore(t, "alice")
	_, err := s.Wrap("bob", v, []byte("dek"))
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("want ErrPermissionDenied, got %v", err)
	}
	t.Logf("v%d: 未授权调用方 bob 被拒绝，原因=ErrPermissionDenied", v)

	if err := s.Grant("bob", v); err != nil {
		t.Fatalf("Grant bob: %v", err)
	}
	if _, err := s.Wrap("bob", v, []byte("dek")); err != nil {
		t.Fatalf("granted bob should wrap: %v", err)
	}
	if err := s.Revoke("bob", v); err != nil {
		t.Fatalf("Revoke bob: %v", err)
	}
	if _, err := s.Wrap("bob", v, []byte("dek")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked bob must be denied, got %v", err)
	}
	t.Logf("v%d: bob 授权->可用->撤销->再次被拒，权限域判定一致", v)
}

func TestRotateKeepsOldCiphertextDecryptable(t *testing.T) {
	s, v1 := newGrantedStore(t, "alice")
	dek := []byte("dek-before-rotation-32bytes!!!")
	wrapped, err := s.Wrap("alice", v1, dek)
	if err != nil {
		t.Fatalf("Wrap v%d: %v", v1, err)
	}
	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	cur, _ := s.CurrentVersion()
	if cur != v2 || v2 == v1 {
		t.Fatalf("after rotation current=%d want %d (old=%d)", cur, v2, v1)
	}
	info, _ := s.Info(v1)
	if info.State != StateDisabled {
		t.Fatalf("old v%d state=%s want DISABLED", v1, info.State)
	}
	got, err := s.Unwrap("alice", v1, wrapped)
	if err != nil || string(got) != string(dek) {
		t.Fatalf("old ciphertext must decrypt after rotation: got=%v err=%v", got, err)
	}
	t.Logf("轮换 v%d->v%d: 旧版本置 DISABLED 仍可解密，新写入走 v%d", v1, v2, v2)
}

func TestRotateFailureRollsBack(t *testing.T) {
	s, v1 := newGrantedStore(t, "alice")
	dek := []byte("dek-before-failed-rotation!!!")
	wrapped, err := s.Wrap("alice", v1, dek)
	if err != nil {
		t.Fatalf("Wrap v%d: %v", v1, err)
	}
	boom := errors.New("simulated backend failure")
	s.SetRotateHook(func() error { return boom })
	if _, err := s.Rotate(); !errors.Is(err, boom) {
		t.Fatalf("want injected failure, got %v", err)
	}
	s.SetRotateHook(nil)

	cur, err := s.CurrentVersion()
	if err != nil || cur != v1 {
		t.Fatalf("after rollback current=%d err=%v, want v%d", cur, err, v1)
	}
	if n := len(s.Versions()); n != 1 {
		t.Fatalf("after rollback versions=%d, want 1 (pending version removed)", n)
	}
	info, _ := s.Info(v1)
	if info.State != StateEnabled {
		t.Fatalf("after rollback v%d state=%s, want ENABLED", v1, info.State)
	}
	got, err := s.Unwrap("alice", v1, wrapped)
	if err != nil || string(got) != string(dek) {
		t.Fatalf("rollback must not affect decryptability: got=%v err=%v", got, err)
	}
	t.Logf("轮换注入失败: 整体回滚，当前版本仍为 v%d(ENABLED)，既有密文可解", v1)

	// 回滚后再次轮换应成功，且版本号复用不出现空洞之外的版本。
	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("Rotate after rollback: %v", err)
	}
	t.Logf("回滚后重试轮换成功: v%d -> v%d", v1, v2)
}

func TestConcurrentRotationAndIO(t *testing.T) {
	s, v1 := newGrantedStore(t, "alice")
	dek := []byte("concurrent-dek-32-byte-material")

	const writers = 8
	const rotations = 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*rotations*4)

	// 并发 Wrap/Unwrap：WrapCurrent 原子完成"取当前版本+包装"，
	// 任何时刻看到的版本都必须可完整完成一次往返，不得出现中间态。
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				v, wrapped, err := s.WrapCurrent("alice", dek)
				if err != nil {
					errs <- fmt.Errorf("writer %d: WrapCurrent: %w", id, err)
					return
				}
				got, err := s.Unwrap("alice", v, wrapped)
				if err != nil || string(got) != string(dek) {
					errs <- fmt.Errorf("writer %d: Unwrap v%d: got=%v err=%v", id, v, got, err)
					return
				}
			}
		}(w)
	}
	// 并发轮换。
	for r := 0; r < rotations; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Rotate(); err != nil {
				errs <- fmt.Errorf("Rotate: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	cur, _ := s.CurrentVersion()
	want := v1 + rotations
	if cur != want {
		t.Fatalf("current=%d want %d after %d rotations", cur, want, rotations)
	}
	t.Logf("并发轮换完成: %d 个写协程 + %d 次轮换，最终当前版本 v%d，无中间态/部分更新可见", writers, rotations, cur)

	// 轮换期间产生的所有历史版本都必须仍可解包（DISABLED 仅禁止加密）。
	for _, info := range s.Versions() {
		if info.ID == cur {
			continue
		}
		if info.State != StateDisabled {
			t.Fatalf("rotated-out v%d state=%s, want DISABLED", info.ID, info.State)
		}
		t.Logf("版本 v%d 状态=%s（判定依据：轮换后旧版本置 DISABLED 仍可解密）", info.ID, info.State)
	}
	t.Logf("当前版本 v%d 状态=ENABLED（判定依据：新写入一律使用最新可用版本）", cur)
}
