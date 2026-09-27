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
