import pytest

from conftest import symlink_or_skip
from devguard.paths import PathNotAllowed, validate_target


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    (r / "proj" / "sub").mkdir(parents=True)
    (r / "proj" / "file.txt").write_text("x")
    (tmp_path / "outside").mkdir()
    return r


def test_allowed_paths(root):
    assert validate_target(str(root / "proj"), [root]) == (root / "proj").resolve()
    assert validate_target(str(root), [root]) == root.resolve()
    assert validate_target(str(root / "proj" / "sub"), [root]) == (root / "proj" / "sub").resolve()


@pytest.mark.parametrize("make", [
    lambda r: str(r.parent / "outside"),            # outside the root
    lambda r: str(r / "proj" / ".." / ".." / "outside"),  # .. escape
    lambda r: str(r / "missing"),                   # does not exist
    lambda r: str(r / "proj" / "file.txt"),         # a file, not a directory
    lambda r: "-rf",                                # option-like
    lambda r: "--config=/etc/passwd",
    lambda r: "",
    lambda r: "   ",
    lambda r: str(r) + "\x00/x",
    lambda r: "/",
])
def test_rejected_paths(root, make):
    with pytest.raises(PathNotAllowed):
        validate_target(make(root), [root])


def test_symlink_pointing_outside_is_rejected(root):
    link = root / "link"
    symlink_or_skip(link, root.parent / "outside", target_is_directory=True)
    with pytest.raises(PathNotAllowed):
        validate_target(str(link), [root])


def test_sibling_prefix_is_not_inside_root(root):
    sibling = root.parent / "root-evil"
    sibling.mkdir()
    with pytest.raises(PathNotAllowed):
        validate_target(str(sibling), [root])


def test_error_lists_roots_but_not_the_probed_path(root):
    with pytest.raises(PathNotAllowed) as exc:
        validate_target("/etc/ssh", [root])
    assert str(root.resolve()) in str(exc.value) and "/etc/ssh" not in str(exc.value)
