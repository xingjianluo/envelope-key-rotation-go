package envelope

import (
	"bytes"
	"errors"
	"testing"

	"github.com/xingjianluo/envelope-key-rotation-go/kms"
)

func TestEncryptDecryptAcrossRotation(t *testing.T) {
	store := kms.NewStore()
	if _, err := store.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	codec := NewCodec(store)

	// 轮换前加密，密文应记录 v1。
	msg := []byte("hello envelope")
	c1, err := codec.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if c1.KeyVersion != "v1" {
		t.Fatalf("cipher version = %s; want v1", c1.KeyVersion)
	}
	t.Logf("判定依据: 活跃版本 v1 -> 密文记录 KeyVersion=%s", c1.KeyVersion)

	// 轮换到 v2。
	if _, err := store.Rotate("v2", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	c2, err := codec.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt after rotate: %v", err)
	}
	if c2.KeyVersion != "v2" {
		t.Fatalf("cipher version after rotate = %s; want v2", c2.KeyVersion)
	}
	t.Logf("判定依据: 轮换后活跃版本 v2 -> 新密文记录 KeyVersion=%s", c2.KeyVersion)

	// 旧密文（v1）仍可解密。
	got, err := codec.Decrypt(c1)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt old cipher: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 密文记录版本 v1 -> 选择 v1 主密钥解包, 解密成功")

	// 停用 v1 后旧密文仍可解密。
	if err := store.Disable("v1"); err != nil {
		t.Fatalf("disable v1: %v", err)
	}
	if _, err := codec.Decrypt(c1); err != nil {
		t.Fatalf("decrypt with disabled version should work: %v", err)
	}
	t.Logf("判定依据: v1 DISABLED -> 解密方向放行")

	// 销毁 v1 后旧密文不可解，原因可区分。
	if err := store.Destroy("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, err := codec.Decrypt(c1); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("decrypt destroyed: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: v1 DESTROYED -> 解密拒绝 ErrVersionDestroyed")

	// 未知版本密文被拒绝。
	bogus := &Cipher{KeyVersion: "vX", WrappedDEK: c2.WrappedDEK, Nonce: c2.Nonce, Ciphertext: c2.Ciphertext}
	if _, err := codec.Decrypt(bogus); !errors.Is(err, kms.ErrUnknownVersion) {
		t.Fatalf("decrypt unknown version: %v; want ErrUnknownVersion", err)
	}
	t.Logf("判定依据: 密文记录版本 vX 不存在 -> ErrUnknownVersion")
}

// 换保：密文从旧版本迁移到新版本后明文不变，源版本销毁后仍照常可解；
// 失败路径保持原密文可解，重试幂等。
func TestReWrap(t *testing.T) {
	store := kms.NewStore()
	if _, err := store.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if _, err := store.CreateVersion("v2"); err != nil {
		t.Fatalf("create v2: %v", err)
	}
	codec := NewCodec(store)

	msg := []byte("migrate me")
	c1, err := codec.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if c1.KeyVersion != "v1" {
		t.Fatalf("cipher version = %s; want v1", c1.KeyVersion)
	}
	t.Logf("判定依据: 活跃版本 v1 -> 原密文 KeyVersion=%s", c1.KeyVersion)

	// 换保到 v2：新密文记录 v2，明文逐字节一致。
	c2, err := codec.ReWrap(c1, "v2")
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if c2.KeyVersion != "v2" {
		t.Fatalf("rewrapped version = %s; want v2", c2.KeyVersion)
	}
	got, err := codec.Decrypt(c2)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt rewrapped: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 换保到 v2 -> KeyVersion=%s, 明文与原密文一致", c2.KeyVersion)

	// 原密文不被修改：v1 仍 ENABLED 时原密文照常可解。
	if got, err := codec.Decrypt(c1); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("original cipher untouched: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 换保不修改原密文 -> 原密文仍按 v1 可解")

	// 源版本销毁后：已迁移密文照常可解，未迁移的原密文不可解。
	if err := store.Destroy("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if got, err := codec.Decrypt(c2); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt migrated after source destroy: got=%q err=%v", got, err)
	}
	if _, err := codec.Decrypt(c1); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("decrypt unmigrated after destroy: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: v1 DESTROYED -> 已迁移密文(v2)可解, 未迁移密文(v1)报 ErrVersionDestroyed")

	// 源版本已销毁：换保失败且原因可区分，不产生半成品密文。
	if _, err := codec.ReWrap(c1, "v2"); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("rewrap from destroyed source: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: 源版本已销毁 -> 换保失败 ErrVersionDestroyed, 不产生半成品密文")
}

// 换保目标约束：停用/销毁/未知版本不能作为换保目标；失败时原密文不受影响。
func TestReWrapTargetConstraints(t *testing.T) {
	store := kms.NewStore()
	if _, err := store.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if _, err := store.CreateVersion("v2"); err != nil {
		t.Fatalf("create v2: %v", err)
	}
	if _, err := store.CreateVersion("v3"); err != nil {
		t.Fatalf("create v3: %v", err)
	}
	codec := NewCodec(store)

	msg := []byte("payload")
	c1, err := codec.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 停用目标：拒绝。
	if err := store.Disable("v2"); err != nil {
		t.Fatalf("disable v2: %v", err)
	}
	if _, err := codec.ReWrap(c1, "v2"); !errors.Is(err, kms.ErrVersionDisabled) {
		t.Fatalf("rewrap to disabled: %v; want ErrVersionDisabled", err)
	}
	t.Logf("判定依据: 目标 v2 DISABLED -> 换保拒绝 ErrVersionDisabled")

	// 销毁目标：拒绝。
	if err := store.Destroy("v2"); err != nil {
		t.Fatalf("destroy v2: %v", err)
	}
	if _, err := codec.ReWrap(c1, "v2"); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("rewrap to destroyed: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: 目标 v2 DESTROYED -> 换保拒绝 ErrVersionDestroyed")

	// 未知目标：拒绝。
	if _, err := codec.ReWrap(c1, "vX"); !errors.Is(err, kms.ErrUnknownVersion) {
		t.Fatalf("rewrap to unknown: %v; want ErrUnknownVersion", err)
	}
	t.Logf("判定依据: 目标 vX 不存在 -> 换保拒绝 ErrUnknownVersion")

	// 上述失败后原密文仍完好可解（无半迁移状态）。
	if got, err := codec.Decrypt(c1); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("original intact after failed rewraps: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 换保失败不触碰原密文 -> 原密文仍按 v1 可解")

	// 换保到 ENABLED 的 v3 成功（目标不必是活跃版本）。
	c3, err := codec.ReWrap(c1, "v3")
	if err != nil {
		t.Fatalf("rewrap to enabled v3: %v", err)
	}
	if got, err := codec.Decrypt(c3); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt rewrapped to v3: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 目标 v3 ENABLED -> 换保成功, KeyVersion=%s 可解", c3.KeyVersion)

	// 幂等：对同一原密文再次换保到 v3，结果等价。
	c3b, err := codec.ReWrap(c1, "v3")
	if err != nil {
		t.Fatalf("idempotent rewrap: %v", err)
	}
	if got, err := codec.Decrypt(c3b); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt idempotent rewrap: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 重复换保幂等 -> 两次结果均可解出同一明文")
}
