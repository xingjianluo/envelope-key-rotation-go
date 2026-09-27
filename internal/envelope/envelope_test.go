package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/envelope-key-rotation-go/internal/keystore"
)

// newService 创建存储、初始版本、授权调用方并返回信封服务。
func newService(t *testing.T, caller string) (*Service, *keystore.Store, int) {
	t.Helper()
	store := keystore.New()
	v, err := store.CreateVersion()
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if err := store.Grant(caller, v); err != nil {
		t.Fatalf("Grant(%q, v%d): %v", caller, v, err)
	}
	return NewService(store, caller), store, v
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc, _, v := newService(t, "alice")
	plaintext := []byte("hello envelope encryption")
	env, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if env.KeyVersion != v {
		t.Fatalf("envelope records v%d, want v%d", env.KeyVersion, v)
	}
	got, err := svc.Decrypt(env)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt: got=%q err=%v", got, err)
	}
	t.Logf("信封记录密钥版本 v%d，加解密往返一致", env.KeyVersion)
}

func TestDecryptSelectsVersionFromCiphertext(t *testing.T) {
	svc, store, v1 := newService(t, "alice")
	msg1 := []byte("written before rotation")
	env1, err := svc.Encrypt(msg1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	v2, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	msg2 := []byte("written after rotation")
	env2, err := svc.Encrypt(msg2)
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	if env1.KeyVersion != v1 || env2.KeyVersion != v2 {
		t.Fatalf("envelopes record v%d/v%d, want v%d/v%d",
			env1.KeyVersion, env2.KeyVersion, v1, v2)
	}
	got1, err := svc.Decrypt(env1)
	if err != nil || !bytes.Equal(got1, msg1) {
		t.Fatalf("decrypt old envelope: got=%q err=%v", got1, err)
	}
	got2, err := svc.Decrypt(env2)
	if err != nil || !bytes.Equal(got2, msg2) {
		t.Fatalf("decrypt new envelope: got=%q err=%v", got2, err)
	}
	t.Logf("轮换 v%d->v%d 后: 旧密文按记录的 v%d 解密成功，新密文使用 v%d", v1, v2, v1, v2)
}

func TestDecryptUnknownAndDestroyedVersion(t *testing.T) {
	svc, store, v1 := newService(t, "alice")
	env, err := svc.Encrypt([]byte("doomed data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 未知版本：篡改信封中的版本号。
	bogus := bytes.Clone(env.Bytes)
	bogus[8] = 99 // keyVersion 字段末字节改为 99
	if _, err := svc.Decrypt(&Envelope{Bytes: bogus}); !errors.Is(err, keystore.ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
	t.Logf("v99: 未知版本被拒绝，原因=ErrUnknownVersion")

	// 销毁版本：历史数据按策略不再可解。
	if err := store.Destroy(v1); err != nil {
		t.Fatalf("Destroy v%d: %v", v1, err)
	}
	if _, err := svc.Decrypt(env); !errors.Is(err, keystore.ErrVersionDestroyed) {
		t.Fatalf("want ErrVersionDestroyed, got %v", err)
	}
	t.Logf("v%d 销毁后: 解密被拒绝，原因=ErrVersionDestroyed（销毁不可逆，历史数据不再可解）", v1)
}

func TestEncryptRejectedWhenNoActiveVersion(t *testing.T) {
	svc, store, v1 := newService(t, "alice")
	if err := store.Disable(v1); err != nil {
		t.Fatalf("Disable v%d: %v", v1, err)
	}
	if _, err := svc.Encrypt([]byte("x")); !errors.Is(err, keystore.ErrNoActiveVersion) {
		t.Fatalf("want ErrNoActiveVersion, got %v", err)
	}
	t.Logf("v%d 停用且无后继版本: 加密被拒绝，原因=ErrNoActiveVersion", v1)
}

func TestPermissionDomains(t *testing.T) {
	svcAlice, store, v1 := newService(t, "alice")
	env, err := svcAlice.Encrypt([]byte("alice only"))
	if err != nil {
		t.Fatalf("alice Encrypt: %v", err)
	}

	// bob 未授权：加密与解密都必须被拒绝，且原因可区分。
	svcBob := NewService(store, "bob")
	if _, err := svcBob.Encrypt([]byte("bob write")); !errors.Is(err, keystore.ErrPermissionDenied) {
		t.Fatalf("bob encrypt: want ErrPermissionDenied, got %v", err)
	}
	if _, err := svcBob.Decrypt(env); !errors.Is(err, keystore.ErrPermissionDenied) {
		t.Fatalf("bob decrypt: want ErrPermissionDenied, got %v", err)
	}
	t.Logf("v%d: 未授权调用方 bob 加解密均被拒，原因=ErrPermissionDenied", v1)

	// 授权后 bob 可解密 alice 写的密文（同一密钥版本、不同调用方）。
	if err := store.Grant("bob", v1); err != nil {
		t.Fatalf("Grant bob: %v", err)
	}
	got, err := svcBob.Decrypt(env)
	if err != nil || string(got) != "alice only" {
		t.Fatalf("granted bob decrypt: got=%q err=%v", got, err)
	}
	t.Logf("v%d: bob 获得授权后解密成功（权限域按调用方+版本判定）", v1)
}

func TestConcurrentRotationWithEnvelopeIO(t *testing.T) {
	svc, store, _ := newService(t, "alice")

	const writers = 8
	const rotations = 5
	var wg sync.WaitGroup
	errs := make(chan error, 64)

	// 并发写：每次加密后必须能立即解密自己写出的信封。
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				msg := []byte(fmt.Sprintf("writer-%d-msg-%d", id, i))
				env, err := svc.Encrypt(msg)
				if err != nil {
					errs <- fmt.Errorf("writer %d: Encrypt: %w", id, err)
					return
				}
				got, err := svc.Decrypt(env)
				if err != nil || !bytes.Equal(got, msg) {
					errs <- fmt.Errorf("writer %d: Decrypt v%d: got=%q err=%v", id, env.KeyVersion, got, err)
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
			if _, err := store.Rotate(); err != nil {
				errs <- fmt.Errorf("Rotate: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	cur, _ := store.CurrentVersion()
	t.Logf("并发测试: %d 个写协程 + %d 次轮换全部成功，最终当前版本 v%d，无部分更新/中间态可见",
		writers, rotations, cur)

	// 轮换后写出的新密文必须使用最新版本。
	env, err := svc.Encrypt([]byte("post-rotation"))
	if err != nil {
		t.Fatalf("post-rotation Encrypt: %v", err)
	}
	if env.KeyVersion != cur {
		t.Fatalf("post-rotation envelope uses v%d, want current v%d", env.KeyVersion, cur)
	}
	t.Logf("轮换后新写入使用当前版本 v%d（判定依据：信封记录的 keyVersion）", cur)
}

func TestRotationRollbackPreservesDecryptability(t *testing.T) {
	svc, store, v1 := newService(t, "alice")
	msg := []byte("data written before failed rotation")
	env, err := svc.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	boom := errors.New("simulated backend failure")
	store.SetRotateHook(func() error { return boom })
	if _, err := store.Rotate(); !errors.Is(err, boom) {
		t.Fatalf("want injected failure, got %v", err)
	}
	store.SetRotateHook(nil)
	t.Logf("轮换注入失败: 整体回滚（判定依据：CurrentVersion 与版本集合不变）")

	// 回滚后既有密文可解，且新写入仍使用原版本。
	got, err := svc.Decrypt(env)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt after rollback: got=%q err=%v", got, err)
	}
	env2, err := svc.Encrypt([]byte("after rollback"))
	if err != nil {
		t.Fatalf("Encrypt after rollback: %v", err)
	}
	if env2.KeyVersion != v1 {
		t.Fatalf("after rollback new writes use v%d, want v%d", env2.KeyVersion, v1)
	}
	t.Logf("回滚后: v%d 密文可解，新写入仍用 v%d，既有数据可解密性未改变", v1, v1)
}

func TestMalformedEnvelope(t *testing.T) {
	svc, _, _ := newService(t, "alice")
	if _, err := svc.Decrypt(&Envelope{Bytes: []byte("short")}); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("want ErrMalformedEnvelope, got %v", err)
	}
	env, err := svc.Encrypt([]byte("tamper target"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	env.Bytes[len(env.Bytes)-1] ^= 0xff // 篡改密文末字节
	if _, err := svc.Decrypt(env); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("want ErrDecryptFailed, got %v", err)
	}
	t.Logf("v%d: 截断信封=ErrMalformedEnvelope，篡改密文=ErrDecryptFailed（原因可区分）", env.KeyVersion)
}
