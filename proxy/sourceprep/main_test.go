package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestApply(t *testing.T) {
	c := change{Before: digest([]byte("abcd")), After: digest([]byte("aXYd")), Edits: []edit{{Offset: 1, Old: "bc", New: "XY"}}}
	b, e := apply([]byte("abcd"), c)
	if e != nil || string(b) != "aXYd" {
		t.Fatal(e)
	}
	if _, e = apply([]byte("other"), c); e == nil {
		t.Fatal("accepted wrong source")
	}
	c.After = "wrong"
	if _, e = apply([]byte("abcd"), c); e == nil {
		t.Fatal("accepted wrong result")
	}
}
func TestSafe(t *testing.T) {
	for _, s := range []string{"../x", "/x", "a/../x", "a\\x", ".", ""} {
		if safe(s) {
			t.Fatal(s)
		}
	}
	if !safe("json/a.go") {
		t.Fatal("valid path")
	}
}
func TestPrepare(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for n, b := range map[string]string{"LICENSE": "license", "a.go": "old"} {
		f, _ := w.Create("github.com/go-jose/go-jose/v3@v3.0.5/" + n)
		f.Write([]byte(b))
	}
	w.Close()
	z := filepath.Join(root, "in.zip")
	os.WriteFile(z, buf.Bytes(), 0600)
	p := plan{ZIP: digest(buf.Bytes()), Files: map[string]change{"a.go": {Before: digest([]byte("old")), After: digest([]byte("new")), Edits: []edit{{Old: "old", New: "new"}}}}}
	j, _ := json.Marshal(p)
	pp := filepath.Join(root, "plan.json")
	os.WriteFile(pp, j, 0600)
	out := filepath.Join(root, "out")
	ev := filepath.Join(root, "evidence")
	if e := prepare(z, pp, out, ev); e != nil {
		t.Fatal(e)
	}
	if e := prepare(z, pp, out, ev); e == nil {
		t.Fatal("overwrote output")
	}
	b, _ := os.ReadFile(filepath.Join(out, "a.go"))
	if string(b) != "new" {
		t.Fatal(string(b))
	}
	if _, e := os.Stat(filepath.Join(ev, "patched-source.tar")); e != nil {
		t.Fatal(e)
	}
	p.ZIP = "wrong"
	j, _ = json.Marshal(p)
	os.WriteFile(pp, j, 0600)
	if e := prepare(z, pp, filepath.Join(root, "bad"), filepath.Join(root, "bad-ev")); e == nil {
		t.Fatal("accepted altered zip")
	}
}
