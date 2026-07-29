package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireFFmpeg skips the test if ffmpeg isn't on PATH — these tests shell out to the
// real binary rather than mocking it, so CI/dev machines without ffmpeg just skip.
func requireFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed, skipping")
	}
}

// generateSampleVideo creates a tiny synthetic .mp4 via ffmpeg's lavfi source, so tests
// don't need a checked-in binary fixture.
func generateSampleVideo(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "sample.mp4")
	cmd := exec.Command("ffmpeg", "-y",
		"-f", "lavfi", "-i", "testsrc=duration=1:size=320x240:rate=15",
		"-f", "lavfi", "-i", "sine=duration=1",
		"-c:v", "libx264", "-c:a", "aac", "-shortest", out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to generate sample video: %v\n%s", err, output)
	}
	return out
}

func TestTranscodeToHLS(t *testing.T) {
	requireFFmpeg(t)

	tmpDir := t.TempDir()
	input := generateSampleVideo(t, tmpDir)
	outDir := filepath.Join(tmpDir, "hls")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := transcodeToHLS(input, outDir); err != nil {
		t.Fatalf("transcodeToHLS failed: %v", err)
	}

	masterPath := filepath.Join(outDir, "master.m3u8")
	if _, err := os.Stat(masterPath); err != nil {
		t.Errorf("master.m3u8 not created: %v", err)
	}

	for _, rendition := range []string{"480p", "720p", "1080p"} {
		playlist := filepath.Join(outDir, rendition, "stream.m3u8")
		if _, err := os.Stat(playlist); err != nil {
			t.Errorf("rendition %s playlist not created: %v", rendition, err)
		}
	}
}
