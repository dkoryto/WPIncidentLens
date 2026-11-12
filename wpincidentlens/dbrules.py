"""Reguły bazy WordPressa: z wierszy tabel użytkowników, ról i opcji powstają wykrycia. Wiersze to nieufne dane."""
from __future__ import annotations

import re

from . import ingest, models
from .analysis import Detection, SourceCoverage, observe

# Minimalna liczba pól wiersza bez listy kolumn, żeby dało się z niego odczytać potrzebne wartości.
CORE_TABLE_CELLS = {"_users": 2, "_usermeta": 4, "_options": 3}


class RowAnalysis:
    """Przyjmuje kolejne wiersze INSERT (``feed``) i po ostatnim oddaje wykrycia (``finish``)."""

    def __init__(self, item: ingest.Evidence) -> None:
        self.item = item
        self.users: dict[str, str] = {}
        self.admins: dict[str, models.Location] = {}  # identyfikator użytkownika → miejsce pierwszego wiersza z rolą
        self.findings: list[Detection] = []
        self.observations: list[models.Observation] = []  # fakty, z których nie powstaje ustalenie
        self.malformed = 0
        self.core_seen = False

    def feed(self, table: str, cols: list[str], cells: list, count: int) -> None:
        """``count`` to numer wiersza w zrzucie (od 1), zapisywany jako położenie faktu."""
        item, users, admins, findings = self.item, self.users, self.admins, self.findings
        if needed := next((cells_needed for suffix, cells_needed in CORE_TABLE_CELLS.items() if table.endswith(suffix)), 0):
            self.core_seen = True
            # Wiersz z wyrażeniem zamiast literału (np. CONCAT(...)) rozpada się na mniej pól, niż ma tabela.
            if (len(cells) != len(cols)) if cols else (len(cells) < needed):
                self.malformed += 1
                return
        if table.endswith("_users"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 2:
                row = {"ID": cells[0], "user_login": cells[1]}
            else:
                return
            if row.get("ID") is not None:
                users[str(row["ID"])] = str(row.get("user_login") or "")
        elif table.endswith("_usermeta"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 4:
                row = {"user_id": cells[1], "meta_key": cells[2], "meta_value": cells[3]}
            else:
                return
            if str(row.get("meta_key") or "").endswith("_capabilities") and "administrator" in str(row.get("meta_value") or ""):
                admins.setdefault(str(row.get("user_id")), models.Location(table=table, key=str(row.get("meta_key"))[:200], row=count))
        elif table.endswith("_options"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 3:
                row = {"option_name": cells[1], "option_value": cells[2]}
            else:
                return
            key = str(row.get("option_name") or "")[:200]
            value = str(row.get("option_value") or "")
            if re.search(r"<script\b|<iframe\b|javascript\s*:", value, flags=re.I):
                findings.append(Detection("SUSPICIOUS_DB_MARKUP", "medium", "low", "database",
                    "Wartość opcji zawiera aktywny znacznik HTML lub schemat JS; wymaga weryfikacji.",
                    observe(item, "OPTION_VALUE_WITH_ACTIVE_MARKUP", models.Location(table=table, key=key, row=count))))

    def finish(self, cover: SourceCoverage, known_admins: set[str]) -> list[Detection]:
        """Porównuje administratorów z zaufaną listą; czego nie da się porównać, trafia do pokrycia jako luka."""
        item, users, admins, findings = self.item, self.users, self.admins, self.findings
        if self.malformed:
            cover.degrade(f"Pominięto {self.malformed} wierszy tabel użytkowników lub opcji o nieoczekiwanej liczbie pól "
                          "(np. wyrażenie SQL zamiast literału)")
        for user_id in sorted(admins):
            login = users.get(user_id, "")
            if not login:
                # Roli nie da się porównać z zaufaną listą: bez luki administrator zniknąłby z raportu bez śladu.
                cover.degrade(f"Rola administratora dla user_id {str(user_id)[:40]} bez odczytanego wiersza w tabeli użytkowników; "
                              "nie można ustalić loginu ani porównać go z zaufaną listą")
                continue
            if known_admins and login not in known_admins:
                findings.append(Detection("UNRECOGNIZED_ADMIN", "high", "medium", "database",
                    "Administrator nie figuruje na dostarczonej, zaufanej liście; nie dowodzi to włamania.",
                    observe(item, "ADMINISTRATOR_ROLE_ROW", admins[user_id], username=login, user_id=user_id)))
        if admins and not known_admins:
            cover.note("Wykryto role administratorów, ale brak wiarygodnej listy porównawczej; sam fakt istnienia admina nie jest alertem")
        return findings
