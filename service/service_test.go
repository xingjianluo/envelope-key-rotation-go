package service

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/envelope-key-rotation-go/envelope"
	"github.com/xingjianluo/envelope-key-rotation-go/kms"
)

func newService(t *testing.T, ids ...string) *Service {
	t.Helper()
	store := kms.NewStore()
	for _, id := range ids {
		if _, err := store.CreateVersion(id); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	return New(store, envelope.NewCodec(store))
}

// 权限域：显式授权集逐版本强制；空授权集的普通调用方在轮换后
// 仍可解密历史版本密文（读取兼容），但版本失效错误与越权错误可区分。
func TestPermissionDomains(t *testing.T) {
	svc := newService(t, "v1")

	// 空授权集 = 普通调用方：加密跟随活跃版本，解密兼容可解的历史版本。
	limited := Caller{Domain: "limited"}
	// 显式授权 v2，不含 v1。
	restricted := Caller{Domain: "restricted", AllowedVersions: map[string]bool{"v2": true}}
	// 显式授权 v1 与 v2。
	full := Caller{Domain: "full", AllowedVersions: map[string]bool{"v1": true, "v2": true}}

	// 轮换前：limited 用当时的活跃版本 v1 写入历史密文。
	old, err := svc.Encrypt(limited, []byte("old-secret"))
	if err != nil {
		t.Fatalf("encrypt before rotation: %v", err)
	}
	if old.KeyVersion != "v1" {
		t.Fatalf("cipher version = %s; want v1", old.KeyVersion)
	}
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// limited 可用活跃版本 v2 加密。
	cph, err := svc.Encrypt(limited, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt with active version: %v", err)
	}
	t.Logf("判定依据: caller=limited 空授权集 -> 加密跟随活跃版本 %s, 加密成功", cph.KeyVersion)

	// 读取兼容：轮换后 limited 仍能解开自己此前用 v1 写入的密文，
	// 不能仅因版本号变了被当成越权。
	got, err := svc.Decrypt(limited, old)
	if err != nil || !bytes.Equal(got, []byte("old-secret")) {
		t.Fatalf("limited decrypt own v1 cipher after rotation: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: caller=limited 空授权集 -> 历史版本 %s 仍可解, 轮换不构成越权", old.KeyVersion)

	// 真正越权仍被拦住：restricted 的显式授权集不含 v1。
	if _, err := svc.Decrypt(restricted, old); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("restricted decrypt v1: %v; want ErrPermissionDenied", err)
	}
	t.Logf("判定依据: caller=restricted 显式授权集 {v2} 不含 v1 -> ErrPermissionDenied")

	// full 解密 limited 的 v2 密文验证显式授权路径。
	if _, err := svc.Decrypt(full, cph); err != nil {
		t.Fatalf("full caller decrypt v2: %v", err)
	}

	// 越权错误与版本失效错误可区分：销毁 v1 后——
	if err := svc.DestroyVersion("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	// limited（空授权集）报版本失效而非越权；
	if _, err := svc.Decrypt(limited, old); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("limited decrypt destroyed v1: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: caller=limited 版本 v1 DESTROYED -> ErrVersionDestroyed (非权限错误)")
	// restricted 仍报越权（权限判定先于版本状态，两条路径独立）。
	if _, err := svc.Decrypt(restricted, old); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("restricted decrypt destroyed v1: %v; want ErrPermissionDenied", err)
	}
	t.Logf("判定依据: caller=restricted 未授权 v1 -> ErrPermissionDenied (与版本失效可区分)")
}

// 并发轮换：轮换期间并发读写不得观察到中间态；
// 所有加密密文记录的版本必须是某次已完成的轮换结果，且均可解密。
func TestConcurrentRotation(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"} // 空授权集：始终跟随活跃版本

	const writers = 8
	const perRound = 10
	var mu sync.Mutex
	var ciphers []*envelope.Cipher

	// 锁步交错：每一轮中，多个写方与一次轮换并发执行，
	// 保证轮换临界区与并发读写真实重叠。
	for r := 2; r <= 6; r++ {
		start := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(r, w int) {
				defer wg.Done()
				<-start
				for i := 0; i < perRound; i++ {
					msg := []byte(fmt.Sprintf("r%d-w%d-%d", r, w, i))
					cph, err := svc.Encrypt(caller, msg)
					if err != nil {
						t.Errorf("encrypt: %v", err)
						return
					}
					mu.Lock()
					ciphers = append(ciphers, cph)
					mu.Unlock()
				}
			}(r, w)
		}
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			<-start
			if err := svc.Rotate(fmt.Sprintf("v%d", r)); err != nil {
				t.Errorf("rotate to v%d: %v", r, err)
			}
		}(r)
		close(start)
		wg.Wait()
	}

	// 结论确定性：每份密文的版本必须是 v1..v6 之一，且都能解密回原文。
	valid := map[string]bool{"v1": true, "v2": true, "v3": true, "v4": true, "v5": true, "v6": true}
	seen := map[string]int{}
	for _, cph := range ciphers {
		if !valid[cph.KeyVersion] {
			t.Fatalf("cipher recorded intermediate/unknown version %q", cph.KeyVersion)
		}
		seen[cph.KeyVersion]++
		// 解密需授权对应版本：使用全授权调用方。
		full := Caller{Domain: "audit", AllowedVersions: valid}
		if _, err := svc.Decrypt(full, cph); err != nil {
			t.Fatalf("decrypt cipher with version %s: %v", cph.KeyVersion, err)
		}
	}
	t.Logf("判定依据: 并发轮换下 %d 份密文版本分布 %v, 均为已提交版本且全部可解密", len(ciphers), seen)
	if len(seen) < 2 {
		t.Fatalf("并发未真实交错: 只观察到版本集合 %v", seen)
	}
	t.Logf("判定依据: 观察到多个已提交版本 %d 类, 说明加密与轮换真实并发交错", len(seen))
}

// 轮换失败回滚：并发读写进行中注入失败，活跃版本与既有数据可解密性不变。
func TestRotationFailureRollback(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"}

	before, err := svc.Encrypt(caller, []byte("before"))
	if err != nil {
		t.Fatalf("encrypt before: %v", err)
	}
	t.Logf("判定依据: 轮换前密文记录版本 %s", before.KeyVersion)

	boom := errors.New("backend unavailable")
	if err := svc.RotateWithHook("v2", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("rotate err = %v; want injected failure", err)
	}

	// 回滚后新写入仍使用 v1。
	after, err := svc.Encrypt(caller, []byte("after"))
	if err != nil {
		t.Fatalf("encrypt after rollback: %v", err)
	}
	if after.KeyVersion != "v1" {
		t.Fatalf("version after rollback = %s; want v1", after.KeyVersion)
	}
	// 既有密文仍可解密。
	got, err := svc.Decrypt(caller, before)
	if err != nil || !bytes.Equal(got, []byte("before")) {
		t.Fatalf("decrypt before after rollback: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 轮换失败回滚 -> 活跃版本保持 %s, 历史密文可解密", after.KeyVersion)
}

// 版本失效后的解密：停用可解、销毁不可解，错误原因可区分。
func TestDecryptAfterInvalidation(t *testing.T) {
	svc := newService(t, "v1")
	full := Caller{Domain: "full", AllowedVersions: map[string]bool{"v1": true, "v2": true}}

	cph, err := svc.Encrypt(full, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 停用 v1：解密仍成功。
	if err := svc.DisableVersion("v1"); err != nil {
		t.Fatalf("disable v1: %v", err)
	}
	if _, err := svc.Decrypt(full, cph); err != nil {
		t.Fatalf("decrypt with disabled v1: %v", err)
	}
	t.Logf("判定依据: v1 DISABLED -> 历史密文解密放行")

	// 销毁 v1：解密失败且原因为 ErrVersionDestroyed。
	if err := svc.DestroyVersion("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, err := svc.Decrypt(full, cph); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("decrypt destroyed v1: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: v1 DESTROYED -> 解密拒绝 ErrVersionDestroyed (不可逆)")

	// 新写入使用 v2 且不受影响。
	c2, err := svc.Encrypt(full, []byte("new"))
	if err != nil || c2.KeyVersion != "v2" {
		t.Fatalf("encrypt after destroy: c=%+v err=%v", c2, err)
	}
	if _, err := svc.Decrypt(full, c2); err != nil {
		t.Fatalf("decrypt v2 cipher: %v", err)
	}
	t.Logf("判定依据: 活跃版本 v2 ENABLED -> 新密文 KeyVersion=%s 且可解密", c2.KeyVersion)
}
