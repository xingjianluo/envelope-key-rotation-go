package service

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/envelope-key-rotation-go/kms"
)

// 单条换保：迁移后明文不变、改由新版本保护；
// 旧版本停用乃至销毁后，已迁移记录照常可解，未迁移密文按原版本规则结算。
func TestMigrateBasic(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"}

	cph, err := svc.Encrypt(caller, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	svc.Records().Put("doc1", cph)
	t.Logf("判定依据: 记录 doc1 初始由版本 %s 保护", cph.KeyVersion)

	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	res := svc.Migrate("doc1", "v2")
	if res.Err != nil || !res.Migrated || res.FromVersion != "v1" || res.ToVersion != "v2" {
		t.Fatalf("migrate result = %+v; want migrated v1->v2", res)
	}
	t.Logf("判定依据: 迁移结果 %+v", res)

	migrated, _ := svc.Records().Get("doc1")
	if migrated.KeyVersion != "v2" {
		t.Fatalf("record version = %s; want v2", migrated.KeyVersion)
	}
	if bytes.Equal(migrated.WrappedDEK, cph.WrappedDEK) {
		t.Fatalf("wrapped DEK unchanged after rewrap; want fresh wrapping under v2")
	}

	// 迁移后明文逐字节不变。
	got, err := svc.Decrypt(caller, migrated)
	if err != nil || !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("decrypt migrated: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 迁移后密文版本 %s, 明文与迁移前一致", migrated.KeyVersion)

	// 未迁移的原密文（调用方持有的副本）在 v1 存活期间仍按老版本解。
	if got, err := svc.Decrypt(caller, cph); err != nil || !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("decrypt unmigrated copy: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 未迁移密文仍按原版本 %s 解密", cph.KeyVersion)

	// 旧版本退役闭环：停用再销毁 v1。
	if err := svc.DisableVersion("v1"); err != nil {
		t.Fatalf("disable v1: %v", err)
	}
	if _, err := svc.Decrypt(caller, migrated); err != nil {
		t.Fatalf("decrypt migrated with v1 disabled: %v", err)
	}
	if err := svc.DestroyVersion("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if got, err := svc.Decrypt(caller, migrated); err != nil || !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("decrypt migrated after v1 destroyed: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: v1 DESTROYED 后, 已迁移记录(版本 %s)照常可解 -> 旧版本安全退役", migrated.KeyVersion)

	// 未迁移的密文此时报版本失效（明确、可区分），而非半迁移错乱。
	if _, err := svc.Decrypt(caller, cph); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("decrypt unmigrated after destroy: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: 未迁移密文 -> ErrVersionDestroyed (原因明确, 非权限错误)")
}

// 批量迁移：混合版本记录逐条独立结算；目标不可用使整批失败但记录保持原值，
// 修正后整批重试成功且幂等；未知记录给出可区分错误。
func TestMigrateBatch(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"}

	// v1 时期写入 r1..r3。
	plaintexts := map[string][]byte{}
	put := func(id string) {
		t.Helper()
		msg := []byte("data-" + id)
		cph, err := svc.Encrypt(caller, msg)
		if err != nil {
			t.Fatalf("encrypt %s: %v", id, err)
		}
		svc.Records().Put(id, cph)
		plaintexts[id] = msg
	}
	put("r1")
	put("r2")
	put("r3")
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	put("r4") // v2 时期写入
	t.Logf("判定依据: r1..r3 记录版本 v1, r4 记录版本 v2")

	// 目标不可用：v3 被停用，整批失败，记录保持原值。
	if _, err := svc.store.CreateVersion("v3"); err != nil {
		t.Fatalf("create v3: %v", err)
	}
	if err := svc.DisableVersion("v3"); err != nil {
		t.Fatalf("disable v3: %v", err)
	}
	ids := []string{"r1", "r2", "r3", "r4"}
	results := svc.MigrateBatch(ids, "v3")
	for _, r := range results {
		if !errors.Is(r.Err, kms.ErrVersionDisabled) {
			t.Fatalf("migrate %s to disabled v3: err=%v; want ErrVersionDisabled", r.ID, r.Err)
		}
	}
	t.Logf("判定依据: 目标 v3 DISABLED -> 整批 %d 条均 ErrVersionDisabled", len(results))
	for id, msg := range plaintexts {
		rec, _ := svc.Records().Get(id)
		if got, err := svc.Decrypt(caller, rec); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("record %s corrupted after failed batch: got=%q err=%v", id, got, err)
		}
	}
	t.Logf("判定依据: 批量失败后全部记录保持原值且可正常解密 (无半迁移状态)")

	// 修正目标后整批重试：含未知记录，逐条结算互不影响。
	results = svc.MigrateBatch(append(append([]string{}, ids...), "ghost"), "v2")
	byID := map[string]MigrateResult{}
	for _, r := range results {
		byID[r.ID] = r
	}
	for _, id := range []string{"r1", "r2", "r3"} {
		r := byID[id]
		if r.Err != nil || !r.Migrated || r.FromVersion != "v1" || r.ToVersion != "v2" {
			t.Fatalf("retry migrate %s: %+v; want migrated v1->v2", id, r)
		}
	}
	if r := byID["r4"]; r.Err != nil || r.Migrated {
		t.Fatalf("retry migrate r4 (already v2): %+v; want idempotent no-op", r)
	}
	if r := byID["ghost"]; !errors.Is(r.Err, ErrUnknownRecord) {
		t.Fatalf("migrate ghost: err=%v; want ErrUnknownRecord", r.Err)
	}
	t.Logf("判定依据: 重试批次 r1..r3 迁移 v1->v2, r4 幂等空操作, ghost -> ErrUnknownRecord")

	// 全部记录解密回原文。
	for id, msg := range plaintexts {
		rec, _ := svc.Records().Get(id)
		if rec.KeyVersion != "v2" {
			t.Fatalf("record %s version = %s; want v2", id, rec.KeyVersion)
		}
		if got, err := svc.Decrypt(caller, rec); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("decrypt %s: got=%q err=%v", id, got, err)
		}
	}
	t.Logf("判定依据: 批次完成后 %d 条记录全部由 v2 保护且明文不变", len(plaintexts))
}

// 迁移与轮换、并发写入同时发生：记录始终处于某个已提交版本的保护之下，
// 最终全部汇聚到目标版本且明文不丢不错。
func TestMigrateConcurrentWithRotation(t *testing.T) {
	// 目标版本 vt 预先创建且全程 ENABLED；轮换只切换活跃指针，不影响 vt。
	svc := newService(t, "vt", "v1")
	caller := Caller{Domain: "any"}

	const records = 64
	plaintexts := map[string][]byte{}
	var mu sync.Mutex

	start := make(chan struct{})
	var wg sync.WaitGroup

	// 写方：持续写入新记录。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < records/4; i++ {
				id := fmt.Sprintf("w%d-%d", w, i)
				msg := []byte(fmt.Sprintf("msg-%s", id))
				cph, err := svc.Encrypt(caller, msg)
				if err != nil {
					t.Errorf("encrypt %s: %v", id, err)
					return
				}
				svc.Records().Put(id, cph)
				mu.Lock()
				plaintexts[id] = msg
				mu.Unlock()
			}
		}(w)
	}

	// 轮换方：连续轮换 v2..v6。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for r := 2; r <= 6; r++ {
			if err := svc.Rotate(fmt.Sprintf("v%d", r)); err != nil {
				t.Errorf("rotate v%d: %v", r, err)
				return
			}
		}
	}()

	// 迁移方：与写入、轮换并发，反复把已出现的记录迁往 vt。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for round := 0; round < 8; round++ {
			mu.Lock()
			ids := make([]string, 0, len(plaintexts))
			for id := range plaintexts {
				ids = append(ids, id)
			}
			mu.Unlock()
			for _, id := range ids {
				if res := svc.Migrate(id, "vt"); res.Err != nil {
					t.Errorf("concurrent migrate %s: %v", id, res.Err)
				}
			}
		}
	}()

	close(start)
	wg.Wait()

	// 收尾：全部记录最终批量迁移到 vt。
	ids := make([]string, 0, len(plaintexts))
	for id := range plaintexts {
		ids = append(ids, id)
	}
	for _, res := range svc.MigrateBatch(ids, "vt") {
		if res.Err != nil {
			t.Fatalf("final migrate %s: %v", res.ID, res.Err)
		}
	}

	// 结论确定性：每份记录都在 vt 保护之下，且解出原始明文。
	seen := map[string]int{}
	for id, msg := range plaintexts {
		rec, ok := svc.Records().Get(id)
		if !ok {
			t.Fatalf("record %s missing", id)
		}
		seen[rec.KeyVersion]++
		if got, err := svc.Decrypt(caller, rec); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("decrypt %s (version %s): got=%q err=%v", id, rec.KeyVersion, got, err)
		}
	}
	if len(seen) != 1 || seen["vt"] != records {
		t.Fatalf("final version distribution = %v; want all %d records on vt", seen, records)
	}
	t.Logf("判定依据: 并发写入+6 轮轮换+并发迁移后, %d 份记录全部汇聚到 vt 且明文逐字节一致", records)
}

// 失效版本硬约束与失败重试：停用/销毁版本不能作为迁移目标；
// 失败不破坏原记录，重试幂等不重复生效；重复销毁结果可区分。
func TestMigrateRetryAndHardConstraints(t *testing.T) {
	svc := newService(t, "v1")
	caller := Caller{Domain: "any"}

	cph, err := svc.Encrypt(caller, []byte("retry-me"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	svc.Records().Put("doc", cph)
	if err := svc.Rotate("v2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 目标停用：迁移失败，错误可区分，记录保持原值可解。
	if _, err := svc.store.CreateVersion("v3"); err != nil {
		t.Fatalf("create v3: %v", err)
	}
	if err := svc.DisableVersion("v3"); err != nil {
		t.Fatalf("disable v3: %v", err)
	}
	res := svc.Migrate("doc", "v3")
	if !errors.Is(res.Err, kms.ErrVersionDisabled) {
		t.Fatalf("migrate to disabled v3: err=%v; want ErrVersionDisabled", res.Err)
	}
	t.Logf("判定依据: 目标 v3 DISABLED -> 迁移拒绝 ErrVersionDisabled (停用版本不可参与加密)")
	rec, _ := svc.Records().Get("doc")
	if rec.KeyVersion != "v1" {
		t.Fatalf("record version after failed migrate = %s; want unchanged v1", rec.KeyVersion)
	}
	if got, err := svc.Decrypt(caller, rec); err != nil || !bytes.Equal(got, []byte("retry-me")) {
		t.Fatalf("record after failed migrate: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 迁移失败 -> 记录保持 v1 且可解, 可安全重试")

	// 目标销毁：错误与停用可区分；销毁不可逆，重复销毁结果可区分。
	if err := svc.DestroyVersion("v3"); err != nil {
		t.Fatalf("destroy v3: %v", err)
	}
	res = svc.Migrate("doc", "v3")
	if !errors.Is(res.Err, kms.ErrVersionDestroyed) {
		t.Fatalf("migrate to destroyed v3: err=%v; want ErrVersionDestroyed", res.Err)
	}
	if err := svc.DestroyVersion("v3"); !errors.Is(err, kms.ErrAlreadyDestroyed) {
		t.Fatalf("re-destroy v3: %v; want ErrAlreadyDestroyed", err)
	}
	t.Logf("判定依据: 目标 v3 DESTROYED -> ErrVersionDestroyed; 重复销毁 -> ErrAlreadyDestroyed")

	// 重试到可用版本成功；再次迁移为幂等空操作，不重复生效。
	res = svc.Migrate("doc", "v2")
	if res.Err != nil || !res.Migrated {
		t.Fatalf("retry migrate to v2: %+v; want success", res)
	}
	before, _ := svc.Records().Get("doc")
	res = svc.Migrate("doc", "v2")
	if res.Err != nil || res.Migrated {
		t.Fatalf("re-migrate to v2: %+v; want idempotent no-op", res)
	}
	after, _ := svc.Records().Get("doc")
	if after != before {
		t.Fatalf("idempotent re-migrate replaced record; want untouched")
	}
	if got, err := svc.Decrypt(caller, after); err != nil || !bytes.Equal(got, []byte("retry-me")) {
		t.Fatalf("decrypt after retry: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 重试成功 v1->v2, 再次迁移幂等命中(记录指针不变), 明文不变")

	// 源版本销毁后迁移给出明确的版本失效错误（不可重试类）。
	if err := svc.DestroyVersion("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	res = svc.Migrate("doc", "v2")
	if res.Err != nil || res.Migrated {
		t.Fatalf("migrate already-migrated record: %+v; want idempotent no-op", res)
	}
	t.Logf("判定依据: 源版本 v1 DESTROYED 不影响已迁移记录, 幂等判定先于源版本解包")
}
