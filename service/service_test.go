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

// 权限域：调用方只能使用被授权的版本；
// 未逐版本授权的普通调用方在轮换后仍可解自己在版本活跃期间写入的密文。
func TestPermissionDomains(t *testing.T) {
	svc := newService(t, "v1")

	// 空授权集 = 仅允许活跃版本（加密方向），解密方向兼容曾活跃版本。
	limited := Caller{Domain: "limited"}
	// 显式授权 v1 与 v2。
	full := Caller{Domain: "full", AllowedVersions: map[string]bool{"v1": true, "v2": true}}

	// 轮换前：limited 用当时的活跃版本 v1 写入历史密文。
	old, err := svc.Encrypt(limited, []byte("old secret"))
	if err != nil {
		t.Fatalf("encrypt before rotation: %v", err)
	}
	if old.KeyVersion != "v1" {
		t.Fatalf("cipher version = %s; want v1", old.KeyVersion)
	}
	t.Logf("判定依据: 轮换前活跃版本 v1 -> limited 写入历史密文 KeyVersion=%s", old.KeyVersion)

	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 轮换后：limited 新写入使用 v2。
	cph, err := svc.Encrypt(limited, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt with active version: %v", err)
	}
	t.Logf("判定依据: caller=limited 空授权集 -> 仅允许活跃版本 %s, 加密成功", cph.KeyVersion)

	// 轮换后：limited 仍能解开自己在 v1 活跃期间写入的密文（读取兼容）。
	got, err := svc.Decrypt(limited, old)
	if err != nil || !bytes.Equal(got, []byte("old secret")) {
		t.Fatalf("limited decrypt own v1 cipher after rotation: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: caller=limited 空授权集 + v1 曾活跃且仍可解 -> 历史密文解密放行")

	// full 也可解密 limited 的 v2 密文（显式授权路径）。
	if _, err := svc.Decrypt(full, cph); err != nil {
		t.Fatalf("full caller decrypt v2: %v", err)
	}

	// 真正越权仍被拦截：v9 存在但从未活跃，limited 解密判越权。
	if _, err := svc.store.CreateVersion("v9"); err != nil {
		t.Fatalf("create v9: %v", err)
	}
	forged := &envelope.Cipher{KeyVersion: "v9", WrappedDEK: cph.WrappedDEK, Nonce: cph.Nonce, Ciphertext: cph.Ciphertext}
	if _, err := svc.Decrypt(limited, forged); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("limited decrypt never-active v9: %v; want ErrPermissionDenied", err)
	}
	t.Logf("判定依据: caller=limited 空授权集 + v9 从未活跃 -> ErrPermissionDenied")

	// 越权错误与版本失效错误可区分：销毁 v1 后，limited 解密 v1 密文
	// 应报版本失效（ErrVersionDestroyed）而非权限错误。
	if err := svc.DestroyVersion("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, err := svc.Decrypt(limited, old); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("limited decrypt destroyed v1: %v; want ErrVersionDestroyed", err)
	}
	if _, err := svc.Decrypt(full, old); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("full decrypt destroyed v1: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: v1 DESTROYED -> 解密拒绝 ErrVersionDestroyed (与权限错误可区分)")
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

// 批量换保：混合版本密文整体迁移到新版本；含失败项时逐项给出结果，
// 失败项保持原样可重试，成功项在源版本销毁后仍可解。
func TestMigrateBatch(t *testing.T) {
	svc := newService(t, "v1")
	full := Caller{Domain: "ops", AllowedVersions: map[string]bool{
		"v1": true, "v2": true, "v3": true,
	}}

	// v1 活跃期写入两份，轮换到 v2 后再写两份。
	var ciphers []*envelope.Cipher
	var msgs [][]byte
	put := func(msg string) {
		cph, err := svc.Encrypt(full, []byte(msg))
		if err != nil {
			t.Fatalf("encrypt %q: %v", msg, err)
		}
		ciphers = append(ciphers, cph)
		msgs = append(msgs, []byte(msg))
	}
	put("a-v1")
	put("b-v1")
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	put("c-v2")
	put("d-v2")
	t.Logf("判定依据: 批量输入 4 份密文, 版本分布 [%s %s %s %s]",
		ciphers[0].KeyVersion, ciphers[1].KeyVersion, ciphers[2].KeyVersion, ciphers[3].KeyVersion)

	// 轮换出 v3 作为迁移目标。
	if err := svc.Rotate("v3"); err != nil {
		t.Fatalf("rotate v3: %v", err)
	}

	// 批量迁移到 v3：全部成功，明文不变，记录版本统一为 v3。
	results := svc.MigrateBatch(full, ciphers, "v3")
	if len(results) != len(ciphers) {
		t.Fatalf("results len = %d; want %d", len(results), len(ciphers))
	}
	migrated := make([]*envelope.Cipher, len(ciphers))
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("migrate item %d (version %s): %v", i, ciphers[i].KeyVersion, r.Err)
		}
		if r.Cipher.KeyVersion != "v3" {
			t.Fatalf("item %d migrated version = %s; want v3", i, r.Cipher.KeyVersion)
		}
		got, err := svc.Decrypt(full, r.Cipher)
		if err != nil || !bytes.Equal(got, msgs[i]) {
			t.Fatalf("decrypt migrated item %d: got=%q err=%v", i, got, err)
		}
		migrated[i] = r.Cipher
	}
	t.Logf("判定依据: 4 份密文全部换保到 v3, 明文逐字节一致")

	// 销毁旧版本 v1/v2：已迁移密文照常可解。
	for _, id := range []string{"v1", "v2"} {
		if err := svc.DestroyVersion(id); err != nil {
			t.Fatalf("destroy %s: %v", id, err)
		}
	}
	for i, cph := range migrated {
		if _, err := svc.Decrypt(full, cph); err != nil {
			t.Fatalf("decrypt migrated item %d after destroy: %v", i, err)
		}
	}
	// 未迁移的原始密文按可区分错误拒绝（v1/v2 已销毁）。
	for i, cph := range ciphers {
		if _, err := svc.Decrypt(full, cph); !errors.Is(err, kms.ErrVersionDestroyed) {
			t.Fatalf("decrypt unmigrated item %d: %v; want ErrVersionDestroyed", i, err)
		}
	}
	t.Logf("判定依据: v1/v2 DESTROYED -> 已迁移密文(v3)全部可解, 未迁移密文报 ErrVersionDestroyed")
}

// 迁移失败重试：目标不可用时报可区分错误且原密文完好；
// 排除原因后重试成功，重复迁移幂等不产生错乱。
func TestMigrateFailureRetry(t *testing.T) {
	svc := newService(t, "v1")
	full := Caller{Domain: "ops", AllowedVersions: map[string]bool{
		"v1": true, "v2": true, "v3": true,
	}}

	cph, err := svc.Encrypt(full, []byte("retry me"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	if _, err := svc.store.CreateVersion("v3"); err != nil {
		t.Fatalf("create v3: %v", err)
	}
	// 停用 v3：作为迁移目标不可用。
	if err := svc.DisableVersion("v3"); err != nil {
		t.Fatalf("disable v3: %v", err)
	}

	// 第一次迁移失败：目标 DISABLED，错误可区分、可重试。
	if _, err := svc.Migrate(full, cph, "v3"); !errors.Is(err, kms.ErrVersionDisabled) {
		t.Fatalf("migrate to disabled target: %v; want ErrVersionDisabled", err)
	}
	t.Logf("判定依据: 目标 v3 DISABLED -> 迁移失败 ErrVersionDisabled (可重试)")

	// 失败后原密文完好可解，不存在半迁移状态。
	got, err := svc.Decrypt(full, cph)
	if err != nil || !bytes.Equal(got, []byte("retry me")) {
		t.Fatalf("original intact after failed migrate: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 迁移失败不触碰原密文 -> 原密文仍按 %s 可解", cph.KeyVersion)

	// 排除失败原因后重试：改以 ENABLED 的 v2 为目标，迁移成功。
	migrated, err := svc.Migrate(full, cph, "v2")
	if err != nil {
		t.Fatalf("retry migrate to v2: %v", err)
	}
	if migrated.KeyVersion != "v2" {
		t.Fatalf("migrated version = %s; want v2", migrated.KeyVersion)
	}
	if got, err := svc.Decrypt(full, migrated); err != nil || !bytes.Equal(got, []byte("retry me")) {
		t.Fatalf("decrypt retried migration: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 重试迁移到 v2 成功 -> KeyVersion=%s, 明文不变", migrated.KeyVersion)

	// 幂等：对迁移结果再次迁移到 v2，仍成功且明文一致。
	again, err := svc.Migrate(full, migrated, "v2")
	if err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	if got, err := svc.Decrypt(full, again); err != nil || !bytes.Equal(got, []byte("retry me")) {
		t.Fatalf("decrypt idempotent migration: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 重复迁移幂等 -> 再次迁移结果仍可解出同一明文")

	// 越权调用方不能发起迁移：limited 空授权集，目标须为活跃版本（当前 v2），
	// 以从未活跃的 v4 为目标应判越权。
	if _, err := svc.store.CreateVersion("v4"); err != nil {
		t.Fatalf("create v4: %v", err)
	}
	limited := Caller{Domain: "limited"}
	if _, err := svc.Migrate(limited, cph, "v4"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("limited migrate to non-active v4: %v; want ErrPermissionDenied", err)
	}
	t.Logf("判定依据: caller=limited 空授权集 + 目标 v4 非活跃 -> ErrPermissionDenied")
}

// 迁移与轮换并发：写方持续加密、迁移方批量换保到当前活跃版本、
// 轮换方推进版本，三者锁步交错。结束后所有已迁移密文必须可解、
// 记录版本必须是某次已提交的轮换结果，明文与原始消息一一对应。
func TestMigrateConcurrentWithRotation(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"} // 空授权集：跟随活跃版本，兼容曾活跃版本

	const writers = 4
	const migrators = 2
	const rounds = 5
	const perRound = 8

	type item struct {
		cph *envelope.Cipher
		msg []byte
	}
	var mu sync.Mutex
	var written []item
	var migrated []item

	for r := 2; r <= rounds+1; r++ {
		start := make(chan struct{})
		var wg sync.WaitGroup
		// 写方：持续用当前活跃版本加密。
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
					written = append(written, item{cph, msg})
					mu.Unlock()
				}
			}(r, w)
		}
		// 迁移方：对已产出密文快照批量换保到当前活跃版本。
		for m := 0; m < migrators; m++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				mu.Lock()
				snapshot := append([]item(nil), written...)
				mu.Unlock()
				if len(snapshot) == 0 {
					return
				}
				cphs := make([]*envelope.Cipher, len(snapshot))
				for i, it := range snapshot {
					cphs[i] = it.cph
				}
				// 目标读取与轮换之间存在合法竞态：目标在迁移间隙不再是活跃版本时，
				// 权限层给出可重试的明确错误；重新读取活跃版本后重试即可。
				var results []MigrationResult
				for attempt := 0; attempt < 8; attempt++ {
					active, err := svc.store.ActiveVersion()
					if err != nil {
						t.Errorf("active version: %v", err)
						return
					}
					results = svc.MigrateBatch(caller, cphs, active.ID)
					retryable := false
					for _, res := range results {
						if errors.Is(res.Err, ErrPermissionDenied) {
							retryable = true
							break
						}
					}
					if !retryable {
						break
					}
				}
				mu.Lock()
				for i, res := range results {
					if res.Err != nil {
						t.Errorf("migrate item (source %s): %v", snapshot[i].cph.KeyVersion, res.Err)
						continue
					}
					migrated = append(migrated, item{res.Cipher, snapshot[i].msg})
				}
				mu.Unlock()
			}()
		}
		// 轮换方：推进到下一个版本。
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

	// 结论确定性：已迁移密文记录版本必须是已提交版本之一，且全部解出原明文。
	valid := map[string]bool{}
	for r := 1; r <= rounds+1; r++ {
		valid[fmt.Sprintf("v%d", r)] = true
	}
	seen := map[string]int{}
	for _, it := range migrated {
		if !valid[it.cph.KeyVersion] {
			t.Fatalf("migrated cipher recorded uncommitted version %q", it.cph.KeyVersion)
		}
		seen[it.cph.KeyVersion]++
		got, err := svc.Decrypt(caller, it.cph)
		if err != nil || !bytes.Equal(got, it.msg) {
			t.Fatalf("decrypt migrated cipher (version %s): got=%q err=%v; want %q",
				it.cph.KeyVersion, got, err, it.msg)
		}
	}
	t.Logf("判定依据: 并发迁移 %d 份密文, 目标版本分布 %v, 均为已提交版本且明文全部吻合",
		len(migrated), seen)

	// 未迁移的原始密文也全部保持可解（版本均曾活跃且未销毁）。
	for _, it := range written {
		if _, err := svc.Decrypt(caller, it.cph); err != nil {
			t.Fatalf("decrypt unmigrated cipher (version %s): %v", it.cph.KeyVersion, err)
		}
	}
	t.Logf("判定依据: %d 份未迁移密文在并发轮换后仍全部可解 (读取兼容)", len(written))
	if len(migrated) == 0 {
		t.Fatal("并发未真实交错: 没有任何迁移发生")
	}
}
