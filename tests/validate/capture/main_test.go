package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The record must name a commit that is still in the repository after a
// squash merge: the merge base of HEAD and origin/main, with the paths
// committed since it listed, never the branch head.
func TestBaseRevisionNamesTheMergeBaseWithMain(t *testing.T) {
	root := t.TempDir()
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
