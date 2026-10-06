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

func TestReWrap(t *testing.T) {
	store := kms.NewStore()
	if _, err := store.CreateVersion("v1"); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	codec := NewCodec(store)

	msg := []byte("rewrap me")
	c1, err := codec.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := store.Rotate("v2", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 换保到 v2：明文不变，改由 v2 保护。
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
	t.Logf("判定依据: 换保 v1->v2 后明文一致, 密文记录版本 %s", c2.KeyVersion)

	// 幂等：已在目标版本时原样返回。
	again, err := codec.ReWrap(c2, "v2")
	if err != nil || again != c2 {
		t.Fatalf("idempotent rewrap: err=%v same=%v; want no-op", err, again == c2)
	}
	t.Logf("判定依据: 重复换保到同一版本 -> 幂等空操作")

	// 硬约束：停用/销毁版本不能作为换保目标。
	if _, err := store.CreateVersion("v3"); err != nil {
		t.Fatalf("create v3: %v", err)
	}
	if err := store.Disable("v3"); err != nil {
		t.Fatalf("disable v3: %v", err)
	}
	if _, err := codec.ReWrap(c1, "v3"); !errors.Is(err, kms.ErrVersionDisabled) {
		t.Fatalf("rewrap to disabled: %v; want ErrVersionDisabled", err)
	}
	if err := store.Destroy("v3"); err != nil {
		t.Fatalf("destroy v3: %v", err)
	}
	if _, err := codec.ReWrap(c1, "v3"); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("rewrap to destroyed: %v; want ErrVersionDestroyed", err)
	}
	t.Logf("判定依据: 目标 v3 DISABLED/DESTROYED -> 换保拒绝, 错误可区分")

	// 源版本销毁后无法再换保，但已换保的密文不受影响。
	if err := store.Destroy("v1"); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, err := codec.ReWrap(c1, "v2"); !errors.Is(err, kms.ErrVersionDestroyed) {
		t.Fatalf("rewrap from destroyed source: %v; want ErrVersionDestroyed", err)
	}
	if got, err := codec.Decrypt(c2); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("decrypt rewrapped after source destroyed: got=%q err=%v", got, err)
	}
	t.Logf("判定依据: 源版本 v1 DESTROYED -> 未换保密文不可再迁移, 已换保密文照常可解")
}
