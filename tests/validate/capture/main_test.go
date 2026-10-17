package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The record must name a commit that is reachable from main after a squash
// merge: the merge base of HEAD and origin/main, with the paths committed
// since it listed, never the branch head.
func TestBaseRevisionNamesTheMergeBaseWithMain(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(rel, content, message string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", "--", rel)
		run("commit", "-q", "-m", message)
		return run("rev-parse", "HEAD")
	}

	run("init", "-q")
	run("symbolic-ref", "HEAD", "refs/heads/main")
	base := commit("a.yaml", "a: 1\n", "first")
	run("update-ref", "refs/remotes/origin/main", base)

	// On main with no tag reachable: the version is the abbreviated commit.
	rev, err := baseRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Commit != base || len(rev.Version) < 7 || !strings.HasPrefix(base, rev.Version) || len(rev.ChangedSinceCommit) != 0 {
		t.Errorf("on main without a tag: got %+v, want commit %s, a version that abbreviates it and no changed paths", rev, base)
	}

	// On main at a tagged commit: the long form still carries the commit.
	run("tag", "v0.1.0")
	rev, err = baseRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Commit != base || !strings.HasPrefix(rev.Version, "v0.1.0-0-g") || !strings.HasPrefix(base, strings.TrimPrefix(rev.Version, "v0.1.0-0-g")) {
		t.Errorf("on main at tag v0.1.0: got %+v, want commit %s and version v0.1.0-0-g followed by its abbreviation", rev, base)
	}

	// On a branch: the record names the merge base, lists what the branch
	// committed, and leaves out the README the capture rewrites.
	run("checkout", "-q", "-b", "topic")
	commit("a.yaml", "a: 2\n", "second")
	head := commit(readmePath, "excerpt\n", "third")
	rev, err = baseRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Commit != base {
		t.Errorf("on topic: commit %s, want the merge base %s, not HEAD %s", rev.Commit, base, head)
	}
	if !strings.HasPrefix(rev.Version, "v0.1.0-0-g") {
		t.Errorf("on topic: version %q, want v0.1.0-0-g followed by the merge base's abbreviation", rev.Version)
	}
	if got := strings.Join(rev.ChangedSinceCommit, " "); got != "a.yaml" {
		t.Errorf("on topic: changedSinceCommit %q, want a.yaml alone (%s is written by the capture)", got, readmePath)
	}
	if out, err := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", rev.Commit, "origin/main").CombinedOutput(); err != nil {
		t.Errorf("recorded commit %s is not reachable from origin/main: %v\n%s", rev.Commit, err, out)
	}

	// Without origin/main the capture refuses instead of recording HEAD.
	run("update-ref", "-d", "refs/remotes/origin/main")
	if _, err := baseRevision(root); err == nil || !strings.Contains(err.Error(), "origin/main") {
		t.Errorf("without origin/main: err = %v, want an error naming origin/main", err)
	}
}

// stubOutput is what the stand-in validator prints.
const stubOutput = `ok   check  1 first
ok   check  2 second
ok   check  3 third
WARNING one
WARNING two

3 of 3 checks reported, 0 failure(s), 2 warning(s)
`

// isolateGit points the git commands a test runs at the test's own
// repositories, whatever the caller exported. Git exports an absolute
// GIT_DIR to hooks and to `git rebase -x` commands, and GIT_INDEX_FILE to
// commit hooks; `git -C <tempdir>` run with those set acts on the repository
// and index they name, not on <tempdir>. The variables that name a
// repository, work tree, index or object store are unset for the test's
// duration, the global and system configuration are left unread, and the
// identity a commit needs comes from the environment rather than from the
// caller's configuration. The caller's values are restored on cleanup.
func isolateGit(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GIT_DIR",
		"GIT_WORK_TREE",
		"GIT_INDEX_FILE",
		"GIT_COMMON_DIR",
		"GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	} {
		unsetenv(t, k)
	}
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "capture test",
		"GIT_AUTHOR_EMAIL":    "capture@example.invalid",
		"GIT_COMMITTER_NAME":  "capture test",
		"GIT_COMMITTER_EMAIL": "capture@example.invalid",
	} {
		t.Setenv(k, v)
	}
}

// unsetenv unsets key for the test's duration. t.Setenv records the value
// the caller had, or that it had none, and restores that on cleanup; it also
// marks the test as one that cannot run in parallel.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	os.Unsetenv(key)
}

// stubRoot returns a git repository holding readme as README.md and, under
// tests/validate, a stand-in validator that prints stubOutput and exits 0.
// Its one commit is also origin/main, as in a clone of main.
func stubRoot(t *testing.T, readme string) string {
	t.Helper()
	isolateGit(t)
	root := t.TempDir()
	writeFile(t, root, readmePath, readme)
	writeFile(t, root, directory+"/go.mod", "module stub\n\ngo 1.22\n")
	writeFile(t, root, directory+"/main.go", "package main\n\nimport \"os\"\n\nfunc main() { os.Stdout.WriteString("+strconv.Quote(stubOutput)+") }\n")
	// The commit and the ref update run no hooks, and the commit needs no
	// identity or signing key from the caller's git config.
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=capture test", "-c", "user.email=capture-test@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "stub"},
		{"-c", "core.hooksPath=/dev/null", "update-ref", "refs/remotes/origin/main", "HEAD"},
	} {
		if _, err := git(root, args...); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A README that capture cannot rewrite fails the run before any file is
// written, so docs/captures/ keeps the previous capture and stays in step
// with the README.
func TestReadmeCheckedBeforeWriting(t *testing.T) {
	cases := []struct{ name, readme, want string }{
		{"no caption line", "# Stub\n\nThe validator prints:\n\n```\nold\n```\n", "has no line starting"},
		{"no blank line after the caption", "# Stub\n\nWhat `go run -mod=vendor .` prints:\n```\nold\n```\n", "must be followed by a blank line"},
		{"no fence after the caption", "# Stub\n\nWhat `go run -mod=vendor .` prints:\n\nold\n", "must be followed by a blank line"},
		{"fence not closed", "# Stub\n\nWhat `go run -mod=vendor .` prints:\n\n```\nold\n", "is not closed"},
	}
	previous := map[string]string{
		outputPath: "previous output\n",
		recordPath: "{\"date\": \"previous\"}\n",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := stubRoot(t, tc.readme)
			for rel, content := range previous {
				writeFile(t, root, rel, content)
			}
			err := capture(root)
			if err == nil || !strings.HasPrefix(err.Error(), readmePath) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("capture returned %v, want a %s error containing %q", err, readmePath, tc.want)
			}
			for rel, content := range previous {
				if got := readFile(t, root, rel); got != content {
					t.Errorf("%s was rewritten by a failed run:\n%s", rel, got)
				}
			}
			if got := readFile(t, root, readmePath); got != tc.readme {
				t.Errorf("%s was rewritten by a failed run:\n%s", readmePath, got)
			}
		})
	}
}

// With the caption and its fence in place, capture writes the output, the
// record and the excerpt under the caption.
func TestCaptureWritesOutputRecordAndExcerpt(t *testing.T) {
	root := stubRoot(t, "# Stub\n\nWhat `go run -mod=vendor .` prints:\n\n```\nold\n```\n\nAfter.\n")
	if err := capture(root); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, outputPath); got != stubOutput {
		t.Errorf("%s:\n%s\nwant:\n%s", outputPath, got, stubOutput)
	}
	var rec record
	if err := json.Unmarshal([]byte(readFile(t, root, recordPath)), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Command != command || rec.Directory != directory || rec.ExitCode != 0 || rec.Output != outputPath {
		t.Errorf("record names %q in %q, exit code %d, output %q", rec.Command, rec.Directory, rec.ExitCode, rec.Output)
	}
	if want := [][2]int{{1, 1}, {3, 4}, {6, 7}}; !reflect.DeepEqual(rec.Excerpt, want) {
		t.Errorf("record excerpt %v, want %v", rec.Excerpt, want)
	}
	want := "# Stub\n\nWhat `go run -mod=vendor .` prints, trimmed ([full output](docs/captures/validate.txt)):\n\n```\n" +
		"ok   check  1 first\n...\nok   check  3 third\nWARNING one\n...\n\n3 of 3 checks reported, 0 failure(s), 2 warning(s)\n" +
		"```\n\nAfter.\n"
	if got := readFile(t, root, readmePath); got != want {
		t.Errorf("%s:\n%s\nwant:\n%s", readmePath, got, want)
	}
}

// Git exports an absolute GIT_DIR to hooks and to `git rebase -x` commands,
// and GIT_INDEX_FILE to commit hooks. The tests of this package build their
// repositories with `git -C <tempdir>`, which those variables override: run
// from a pre-commit hook of a linked worktree, they used to commit, tag and
// move refs in that worktree's repository and move its HEAD and index. This
// test runs the other tests in a child process whose GIT_DIR and
// GIT_INDEX_FILE name a linked worktree of a scratch repository, and checks
// that they pass and that the scratch repository's refs, HEADs and index are
// as they were.
func TestTestsLeaveTheCallersRepositoryUnchanged(t *testing.T) {
	isolateGit(t)
	dir := t.TempDir()
	outer, wt := filepath.Join(dir, "outer"), filepath.Join(dir, "wt")
	run := func(dir string, args ...string) string {
		t.Helper()
		out, err := git(dir, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	commit := func(dir, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		run(dir, "add", "--", name)
		run(dir, "commit", "-q", "-m", name)
	}
	run(dir, "init", "-q", outer)
	run(outer, "symbolic-ref", "HEAD", "refs/heads/main")
	commit(outer, "one.txt")
	run(outer, "worktree", "add", "-q", "-b", "topic", wt)
	commit(wt, "two.txt")
	snapshot := func() string {
		t.Helper()
		return strings.Join([]string{
			run(outer, "for-each-ref", "--format=%(refname) %(objectname)"),
			"outer HEAD " + run(outer, "symbolic-ref", "HEAD"),
			"wt HEAD " + run(wt, "symbolic-ref", "HEAD"),
			"wt status [" + run(wt, "status", "--porcelain") + "]",
		}, "\n")
	}
	before := snapshot()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gitDir := run(wt, "rev-parse", "--absolute-git-dir")
	cmd := exec.Command(exe, "-test.skip=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir, "GIT_INDEX_FILE="+filepath.Join(gitDir, "index"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("the other tests failed with GIT_DIR=%s: %v\n%s", gitDir, err, out)
	}
	if after := snapshot(); after != before {
		t.Errorf("the other tests changed the repository GIT_DIR named:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
