import configparser
import re
import subprocess
import sys


def release_commit(tag):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("Expected a stable release tag, such as v3.4.1")

    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], text=True
    ).strip()
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "origin/master"], check=True
    )
    metadata = configparser.ConfigParser()
    metadata.read_string(subprocess.check_output(
        ["git", "show", f"{commit}:setup.cfg"], text=True
    ))
    if metadata["metadata"]["version"] != tag[1:]:
        raise ValueError("Release tag does not match setup.cfg version")
    return commit


if __name__ == "__main__":
    print(release_commit(sys.argv[1]))
