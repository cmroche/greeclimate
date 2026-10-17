from pathlib import Path
import subprocess
import sys

import pytest


VALIDATOR = Path(__file__).resolve().parents[1] / ".github/scripts/validate-release.py"


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-c", "tag.gpgsign=false", "-c", "commit.gpgsign=false",
         "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", *args],
        cwd=repo, text=True
    ).strip()


@pytest.fixture
def release_repo(tmp_path):
    git(tmp_path, "init", "--initial-branch=master")
    (tmp_path / "setup.cfg").write_text("[metadata]\nversion = 1.2.3\n")
    git(tmp_path, "add", "setup.cfg")
    git(tmp_path, "commit", "-m", "Release fixture")
    git(tmp_path, "update-ref", "refs/remotes/origin/master", "HEAD")
    return tmp_path


def validate(repo, tag):
    return subprocess.run(
        [sys.executable, str(VALIDATOR), tag], cwd=repo, text=True, capture_output=True
    )


@pytest.mark.parametrize("tag_options", [[], ["-a", "-m", "Release"]])
def test_release_tag_resolves_to_merged_commit(release_repo, tag_options):
    git(release_repo, "tag", *tag_options, "v1.2.3")
    result = validate(release_repo, "v1.2.3")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == git(release_repo, "rev-parse", "HEAD")


def test_release_version_must_match_tag(release_repo):
    git(release_repo, "tag", "v1.2.4")
    result = validate(release_repo, "v1.2.4")
    assert result.returncode != 0
    assert result.stdout == ""


def test_release_commit_must_be_on_master(release_repo):
    (release_repo / "setup.cfg").write_text("[metadata]\nversion = 1.2.4\n")
    git(release_repo, "add", "setup.cfg")
    git(release_repo, "commit", "-m", "Unmerged release")
    git(release_repo, "tag", "v1.2.4")
    result = validate(release_repo, "v1.2.4")
    assert result.returncode != 0
    assert result.stdout == ""


def test_release_tag_must_exist(release_repo):
    result = validate(release_repo, "v1.2.3")
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("tag", ["master", "--help", "v1.2.3\ncommit=bad", "v1.2.3-rc.1", "v01.2.3"])
def test_release_rejects_non_stable_tag_names(release_repo, tag):
    result = validate(release_repo, tag)
    assert result.returncode != 0
    assert result.stdout == ""
