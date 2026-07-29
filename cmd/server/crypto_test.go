package main

import "testing"

func init() {
	if err := loadEmailEncryptionKey(); err != nil {
		panic(err)
	}
}

func TestEncryptDecryptEmail_Roundtrip(t *testing.T) {
	plain := "user@example.com"
	enc, err := encryptEmail(plain)
	if err != nil {
		t.Fatalf("encryptEmail: %v", err)
	}
	if enc == plain {
		t.Error("expected ciphertext to differ from plaintext")
	}

	dec, err := decryptEmail(enc)
	if err != nil {
		t.Fatalf("decryptEmail: %v", err)
	}
	if dec != plain {
		t.Errorf("expected %q, got %q", plain, dec)
	}
}

func TestEncryptEmail_NonDeterministic(t *testing.T) {
	plain := "same@example.com"
	enc1, err := encryptEmail(plain)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := encryptEmail(plain)
	if err != nil {
		t.Fatal(err)
	}
	if enc1 == enc2 {
		t.Error("expected different ciphertexts for the same plaintext (random nonce)")
	}
}

func TestEncryptDecryptEmail_Empty(t *testing.T) {
	enc, err := encryptEmail("")
	if err != nil {
		t.Fatal(err)
	}
	if enc != "" {
		t.Errorf("expected empty ciphertext for empty input, got %q", enc)
	}
	dec, err := decryptEmail("")
	if err != nil {
		t.Fatal(err)
	}
	if dec != "" {
		t.Errorf("expected empty plaintext for empty input, got %q", dec)
	}
}

func TestDecryptEmail_RejectsGarbage(t *testing.T) {
	if _, err := decryptEmail("not-valid-base64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	if _, err := decryptEmail("dG9vc2hvcnQ="); err == nil {
		t.Error("expected error for ciphertext shorter than nonce size")
	}
}
