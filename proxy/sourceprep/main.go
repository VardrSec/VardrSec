// Source preparation is deliberately stdlib-only and runs before the offline build.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type edit struct {
	Offset int    `json:"offset"`
	Old    string `json:"old"`
	New    string `json:"new"`
}
type change struct {
	Before  string `json:"before_sha256"`
	After   string `json:"after_sha256"`
	NewFile bool   `json:"new_file"`
	Edits   []edit `json:"edits"`
}
type plan struct {
	Upstream string            `json:"upstream_commit"`
	Security string            `json:"security_commit"`
	ZIP      string            `json:"upstream_zip_sha256"`
	Files    map[string]change `json:"files"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func apply(b []byte, c change) ([]byte, error) {
	if digest(b) != c.Before {
		return nil, fmt.Errorf("unexpected original hash")
	}
	limit := len(b)
	for i := len(c.Edits) - 1; i >= 0; i-- {
		e := c.Edits[i]
		end := e.Offset + len(e.Old)
		if e.Offset < 0 || end > limit || string(b[e.Offset:end]) != e.Old {
			return nil, fmt.Errorf("invalid edit")
		}
		b = append(append(append([]byte{}, b[:e.Offset]...), []byte(e.New)...), b[end:]...)
		limit = e.Offset
	}
	if digest(b) != c.After {
		return nil, fmt.Errorf("unexpected patched hash")
	}
	return b, nil
}
func safe(n string) bool {
	return n != "" && n != "." && !strings.Contains(n, "\\") && !strings.HasPrefix(n, "/") && path.Clean(n) == n && n != ".." && !strings.HasPrefix(n, "../")
}
func prepare(zipPath, planPath, dst, evidence string) error {
	raw, err := os.ReadFile(zipPath)
	if err != nil {
		return err
	}
	praw, err := os.ReadFile(planPath)
	if err != nil {
		return err
	}
	var p plan
	if err = json.Unmarshal(praw, &p); err != nil {
		return err
	}
	if digest(raw) != p.ZIP {
		return fmt.Errorf("upstream ZIP hash mismatch")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	total := 0
	prefix := "github.com/go-jose/go-jose/v3@v3.0.5/"
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) {
			return fmt.Errorf("unexpected module prefix")
		}
		n := strings.TrimPrefix(f.Name, prefix)
		if !safe(n) || f.Mode()&os.ModeSymlink != 0 || f.FileInfo().IsDir() {
			return fmt.Errorf("unsafe module member")
		}
		if _, ok := files[n]; ok {
			return fmt.Errorf("duplicate member")
		}
		if f.UncompressedSize64 > 8<<20 {
			return fmt.Errorf("oversize member")
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, 8<<20+1))
		r.Close()
		if e != nil {
			return e
		}
		total += len(b)
		if len(b) > 8<<20 || total > 64<<20 {
			return fmt.Errorf("oversize module")
		}
		files[n] = b
	}
	for n, c := range p.Files {
		if !safe(n) {
			return fmt.Errorf("unsafe patch path")
		}
		b, exists := files[n]
		if exists == c.NewFile {
			return fmt.Errorf("wrong patch file existence")
		}
		b, err = apply(b, c)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		files[n] = b
	}
	// Validate everything before creating output. Never overwrite an existing directory.
	if err = os.Mkdir(dst, 0755); err != nil {
		return err
	}
	if err = os.Mkdir(evidence, 0755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	archive, err := os.OpenFile(filepath.Join(evidence, "patched-source.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(archive)
	for _, n := range names {
		b := files[n]
		f := filepath.Join(dst, filepath.FromSlash(n))
		if err = os.MkdirAll(filepath.Dir(f), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(f, b, 0644); err != nil {
			return err
		}
		h := &tar.Header{Name: n, Mode: 0644, Size: int64(len(b)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err = tw.Write(b); err != nil {
			return err
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if err = archive.Close(); err != nil {
		return err
	}
	retained := map[string][]byte{"upstream-module.zip": raw, "backport.json": praw, "LICENSE": files["LICENSE"]}
	for n, b := range retained {
		if err = os.WriteFile(filepath.Join(evidence, n), b, 0644); err != nil {
			return err
		}
	}
	sums := map[string]string{}
	for _, n := range []string{"upstream-module.zip", "backport.json", "LICENSE", "patched-source.tar"} {
		b, e := os.ReadFile(filepath.Join(evidence, n))
		if e != nil {
			return e
		}
		sums[n] = digest(b)
	}
	receipt := map[string]interface{}{"schema": 1, "upstream_commit": p.Upstream, "security_commit": p.Security, "module": "github.com/go-jose/go-jose/v3", "upstream_version": "v3.0.5", "security_backport": "RSA JWK bounds and early private JOSE header rejection", "sha256": sums, "scanner_clearance": false, "release_clearance": false}
	b, _ := json.MarshalIndent(receipt, "", "  ")
	return os.WriteFile(filepath.Join(evidence, "source.json"), append(b, '\n'), 0644)
}
func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: sourceprep upstream.zip backport.json new-source-directory new-evidence-directory")
		os.Exit(2)
	}
	if err := prepare(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
