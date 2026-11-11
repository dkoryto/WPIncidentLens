"""Klasyfikacja plików po ścieżce (R-51)."""
import pytest

from wpincidentlens.fileclass import FileClass, classify


@pytest.mark.parametrize("rel, expected", [
    ("index.php", FileClass.CORE),
    ("wp-login.php", FileClass.CORE),
    ("wp-includes/version.php", FileClass.CORE),
    ("wp-admin/css/site.css", FileClass.CORE),
    ("wp-config.php", FileClass.CONFIG),
    (".htaccess", FileClass.CONFIG),
    ("wp-content/object-cache.php", FileClass.DROPIN),
    ("wp-content/mu-plugins/loader.php", FileClass.MU_PLUGIN),
    ("wp-content/plugins/demo/demo.php", FileClass.PLUGIN),
    ("wp-content/themes/demo/footer.php", FileClass.THEME),
    ("wp-content/uploads/2026/11/photo.jpg", FileClass.UPLOAD),
    ("wp-content/languages/pl_PL.mo", FileClass.LANGUAGE),
], ids=lambda value: str(value))
def test_standard_layout_paths_get_their_class(rel, expected):
    assert classify(rel) is expected


@pytest.mark.parametrize("rel", [
    "wp-content/index.php",                 # zwykły plik w wp-content, nie drop-in
    "wp-content/uploads",                   # sam katalog, bez pliku w środku
    "backup/wp-includes/version.php",       # kopia poza standardowym położeniem
    "wp-includes.php.bak",
    "readme.html",
    "wp-content/cache/object-cache.php",    # nazwa drop-inu, ale nie bezpośrednio w wp-content
], ids=lambda value: str(value))
def test_paths_outside_the_standard_layout_are_other(rel):
    assert classify(rel) is FileClass.OTHER
