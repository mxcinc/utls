package tls

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestCertificateMsgTLS13PreservesOriginalBytes(t *testing.T) {
	// 未知证书扩展会在重新编码时丢失，握手摘要必须使用收到的原始消息。
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte("dummy-leaf-der"))
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x1234)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte("ext-payload"))
				})
			})
		})
	})
	wire, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var m certificateMsgTLS13
	if !m.unmarshal(wire) {
		t.Fatal("unmarshal failed")
	}
	remarshaled, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(remarshaled, wire) {
		t.Fatal("test must exercise a certificate whose re-marshal differs from its wire encoding")
	}
	h := sha256.New()
	if err := transcriptMsg(&m, h); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(wire)
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("transcriptMsg must hash the original Certificate bytes")
	}
}
