"""Reguły plików: ścieżka i treść. Dostają bajty już przeczytane przez SecureIngest; niczego nie wykonują."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from . import ingest
from .analysis import Detection, seen_in

CODE_SUFFIXES = {".php", ".phtml", ".phar", ".inc"}


def wants_content(rel: str) -> bool:
    """Czy reguły treści obejmują ten plik (tylko takie pliki SecureIngest zatrzymuje w pamięci)."""
    path = PurePosixPath(rel)
    return path.suffix.lower() in CODE_SUFFIXES or path.name in (".htaccess", ".user.ini")


def is_code_in_uploads(rel: str) -> bool:
    return rel.startswith("wp-content/uploads/") and PurePosixPath(rel).suffix.lower() in CODE_SUFFIXES


def path_rules(item: ingest.Evidence) -> list[Detection]:
    """Reguły zależne tylko od ścieżki: pominięcie odczytu (hardlink, symlink, błąd) nie może ich wyłączyć."""
    if not is_code_in_uploads(item.rel):
        return []
    if item.sha256 is None:
        return [Detection("EXECUTABLE_IN_UPLOADS", "high", "low", "file",
                          "Plik wykonywalny PHP w uploads; treść nieodczytana, wymaga ręcznej analizy.",
                          seen_in(item, "PHP_FILE_IN_UPLOADS"))]
    return [Detection("EXECUTABLE_IN_UPLOADS", "high", "medium", "file",
                      "Plik wykonywalny PHP w uploads; wymaga analizy kontekstu.", seen_in(item, "PHP_FILE_IN_UPLOADS"))]


def content_rules(item: ingest.Evidence) -> list[Detection]:
    """Heurystyki treści pliku, którego bajty zatrzymano (``item.content``)."""
    found = []
    raw = item.content.lower()
    if re.search(rb"eval\s*\(\s*base64_decode\s*\(", raw):
        found.append(Detection("SUSPICIOUS_PHP_EVAL_DECODE", "high", "medium", "file",
                               "Wykryto łańcuch eval(base64_decode(...)); to heurystyka, nie dowód malware.",
                               seen_in(item, "EVAL_BASE64_DECODE_PATTERN")))
    if re.search(rb"\$_(?:post|get|request)\s*\[.{0,120}\].{0,150}(?:shell_exec|system|passthru)\s*\(", raw, re.DOTALL):
        found.append(Detection("REQUEST_TO_COMMAND_EXEC", "high", "medium", "file",
                               "Potencjalne powiązanie danych żądania z wykonaniem komendy; wymaga ręcznej weryfikacji.",
                               seen_in(item, "REQUEST_INPUT_NEAR_COMMAND_EXEC_PATTERN")))
    return found
