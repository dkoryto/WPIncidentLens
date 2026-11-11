"""Klasyfikacja pliku po ścieżce względnej w drzewie witryny (R-51). To wskazówka z położenia, nie dowód pochodzenia."""
from __future__ import annotations

from enum import StrEnum


class FileClass(StrEnum):
    CORE = "CORE"
    CONFIG = "CONFIG"
    DROPIN = "DROPIN"
    MU_PLUGIN = "MU_PLUGIN"
    PLUGIN = "PLUGIN"
    THEME = "THEME"
    UPLOAD = "UPLOAD"
    LANGUAGE = "LANGUAGE"
    OTHER = "OTHER"


# Pliki ładowane przez WordPressa z wp-content bez wpisu w bazie (drop-ins).
DROPINS = frozenset({"advanced-cache.php", "db.php", "db-error.php", "install.php", "maintenance.php", "object-cache.php",
                     "php-error.php", "fatal-error-handler.php", "sunrise.php", "blog-deleted.php", "blog-inactive.php",
                     "blog-suspended.php"})
CONFIG_NAMES = frozenset({"wp-config.php", ".htaccess", ".user.ini", "php.ini"})
_CONTENT_DIRS = {"mu-plugins": FileClass.MU_PLUGIN, "plugins": FileClass.PLUGIN, "themes": FileClass.THEME,
                 "uploads": FileClass.UPLOAD, "languages": FileClass.LANGUAGE}
# Ładowane automatycznie przy każdym żądaniu: nowy plik tutaj to mechanizm utrwalenia, nie zwykły dodatek.
AUTOLOADED = frozenset({FileClass.MU_PLUGIN, FileClass.DROPIN})


def classify(rel: str) -> FileClass:
    """Klasa pliku według standardowego układu WordPressa; ścieżka jest względna do katalogu witryny, z ukośnikami ``/``."""
    parts = rel.split("/")
    if len(parts) == 1:
        if parts[0] in CONFIG_NAMES:
            return FileClass.CONFIG
        if parts[0] in ("index.php", "xmlrpc.php") or (parts[0].startswith("wp-") and parts[0].endswith(".php")):
            return FileClass.CORE
        return FileClass.OTHER
    if parts[0] in ("wp-admin", "wp-includes"):
        return FileClass.CORE
    if parts[0] != "wp-content":
        return FileClass.OTHER
    if len(parts) == 2:
        return FileClass.DROPIN if parts[1] in DROPINS else FileClass.OTHER
    return _CONTENT_DIRS.get(parts[1], FileClass.OTHER)
