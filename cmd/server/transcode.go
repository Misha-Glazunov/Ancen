package main

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

// transcodeToHLS гонит ffmpeg над inputPath и кладёт adaptive HLS (480p/720p/1080p
// + master.m3u8) в outDir. ponytail: синхронно, без очереди задач — эндпоинт
// используется редко (ручная заливка серии); апгрейд до асинхронного воркера,
// если появится массовая заливка через будущую админку.
func transcodeToHLS(inputPath, outDir string) error {
	for _, name := range []string{"480p", "720p", "1080p"} {
		if err := os.MkdirAll(filepath.Join(outDir, name), 0755); err != nil {
			return err
		}
	}

	args := []string{
		"-y", "-i", inputPath,
		"-filter_complex", "[0:v]split=3[v1][v2][v3];" +
			"[v1]scale=w=842:h=480[v1out];" +
			"[v2]scale=w=1280:h=720[v2out];" +
			"[v3]scale=w=1920:h=1080[v3out]",
		"-map", "[v1out]", "-c:v:0", "libx264", "-b:v:0", "800k",
		"-map", "[v2out]", "-c:v:1", "libx264", "-b:v:1", "2800k",
		"-map", "[v3out]", "-c:v:2", "libx264", "-b:v:2", "5000k",
		"-map", "a:0", "-c:a:0", "aac", "-b:a:0", "128k",
		"-map", "a:0", "-c:a:1", "aac", "-b:a:1", "128k",
		"-map", "a:0", "-c:a:2", "aac", "-b:a:2", "128k",
		"-f", "hls",
		"-hls_time", "6",
		"-hls_playlist_type", "vod",
		"-hls_flags", "independent_segments",
		"-master_pl_name", "master.m3u8",
		"-var_stream_map", "v:0,a:0,name:480p v:1,a:1,name:720p v:2,a:2,name:1080p",
		// path.Join (не filepath.Join): эти пути попадают в master.m3u8 как
		// относительные URI, а m3u8/HLS всегда использует "/", даже на Windows.
		"-hls_segment_filename", path.Join("%v", "data%03d.ts"),
		path.Join("%v", "stream.m3u8"),
	}

	// master.m3u8 без явного пути пишется ffmpeg-ом в рабочую директорию процесса,
	// а не рядом с output-паттерном — поэтому Dir=outDir и все пути в args относительные.
	cmd := exec.Command("ffmpeg", args...)
	cmd.Dir = outDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
