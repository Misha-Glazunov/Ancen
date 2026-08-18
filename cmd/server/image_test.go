package main

import (
	"image"
	"image/png"
	"io"
	"os"
	"testing"
)

// TestNormalizeUploadedImage — самопроверка ресайза: кладём 2000x1000 PNG,
// ждём JPEG не шире 900 по длинной стороне (аспект сохранён).
func TestNormalizeUploadedImage(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2000, 1000))
	tmpIn, err := os.CreateTemp("", "test-src-*.png")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpIn.Name())
	if err := png.Encode(tmpIn, src); err != nil {
		t.Fatal(err)
	}
	if _, err := tmpIn.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	outPath, err := normalizeUploadedImage(tmpIn, 900)
	if err != nil {
		t.Fatalf("normalizeUploadedImage: %v", err)
	}
	defer os.Remove(outPath)

	out, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	decoded, format, err := image.Decode(out)
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if format != "jpeg" {
		t.Fatalf("want jpeg output, got %s", format)
	}
	b := decoded.Bounds()
	if b.Dx() != 900 || b.Dy() != 450 {
		t.Fatalf("want 900x450, got %dx%d", b.Dx(), b.Dy())
	}
}
