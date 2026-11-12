"""Oś czasu i korelacja ustaleń z różnych źródeł (ADR 0007 pkt 6 i 8). Bez dostępu do plików.

Korelacja to relacja między faktami (``SAME_PATH``, ``NEAR_IN_TIME``, specyfikacja §8.3), nigdy przyczynowość:
nie twierdzi, że żądanie zapisało albo wykonało plik. Relacje są identyfikatorami reguł, więc schemat ``poc-1`` się nie zmienia.
"""
from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import filerules, models, redact, rules
from .analysis import Detection

DEFAULT_WINDOW_SECONDS = 900
MAX_REQUESTS_PER_FINDING = 20  # obserwacje żądań wskazane w jednym ustaleniu; reszta jest tylko policzona w wyjaśnieniu
MAX_FINDINGS_PER_RULE = 200    # ponad limit powstaje luka pokrycia logów z łączną liczbą wykryć
REQUEST_KIND = "HTTP_REQUEST"
TIMELINE_EVENT = "HTTP_REQUEST"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICROSECOND = timedelta(microseconds=1)
_NOT_CAUSAL = ("To nie jest związek przyczynowy: relacja nie dowodzi, że żądanie zapisało albo wykonało plik, "
               "ani że zakończyło się sukcesem; status HTTP 200 też tego nie dowodzi.")


@dataclass(frozen=True)
class Correlation:
    """Ustalenia korelacyjne, obserwacje żądań, na które wskazują (muszą trafić do raportu), i noty o limitach."""
    findings: tuple[models.Finding, ...] = ()
    requests: tuple[models.Observation, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _File:
    """Plik z obrazu witryny, który ma co najmniej jedno ustalenie plikowe."""
    path: str
    mtime_ns: int | None
    observations: tuple[str, ...]


@dataclass(frozen=True)
class Focus:
    """Które żądania do plików kodu korelacja może wykorzystać (ADR 0007 pkt 7, przegląd M4): ścieżki plików kodu
    z ustaleniem plikowym (``SAME_PATH``) i przedziały czasu ``mtime`` ± (okno + niepewność zegara) plików z ustaleniem
    (``NEAR_IN_TIME``). Parser logów trzyma w pamięci tylko żądania pasujące do niego, więc zalew żądań do innych
    ścieżek kodu nie wyczerpuje limitu żądań. Ścieżki są po ``redact.neutralise``, jak atrybut ``path`` żądania."""
    paths: frozenset[str] = frozenset()
    windows: tuple[tuple[int, int], ...] = ()  # rozłączne, rosnące przedziały [początek, koniec] w ns od epoki

    def wants(self, path: str, timestamp_utc: str | None) -> bool:
        if path in self.paths:
            return True
        if timestamp_utc is None or not self.windows:
            return False
        moment = _ns(timestamp_utc)
        at = bisect.bisect_right(self.windows, (moment, float("inf"))) - 1
        return at >= 0 and self.windows[at][0] <= moment <= self.windows[at][1]


def check_window(window_seconds: object) -> None:
    """Okno korelacji to wybór operatora, nie dane: niepoprawne jest błędem wywołania (``ValueError``), nie luką."""
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds <= 0:
        raise ValueError("okno korelacji musi być dodatnią liczbą całkowitą sekund")


def focus(detections: list[Detection], evidence: Mapping[str, models.Evidence], window_seconds: int = DEFAULT_WINDOW_SECONDS,
          uncertainty: int | None = None) -> Focus:
    """``Focus`` z ustaleń plikowych znanych przed analizą logów; ``uncertainty`` to niepewność zegara logów w sekundach.

    Obejmuje wszystko, czego ``correlate`` może użyć: ``SAME_PATH`` dla plików kodu i ``NEAR_IN_TIME`` z tą samą
    granicą okna (włącznie) poszerzoną o niepewność zegara zadeklarowaną dla wszystkich żądań przebiegu.
    """
    reach = (window_seconds + max(uncertainty or 0, 0)) * 10**9
    paths, spans = set(), []
    for file in _flagged_files(detections, evidence):
        if _is_code(file.path):
            paths.add(redact.neutralise(file.path))
        if file.mtime_ns is not None:
            spans.append((file.mtime_ns - reach, file.mtime_ns + reach))
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], stop))
        else:
            merged.append((start, stop))
    return Focus(frozenset(paths), tuple(merged))


def _finding(rule: str, severity: str, confidence: str, reason: str, observations: tuple[str, ...],
             notes: list[str]) -> models.Finding:
    """Ustalenie korelacyjne przez rejestr reguł; naruszenie deklaracji reguły trafia do not (luka pokrycia ``logs``)."""
    return rules.finding(rule, "correlation", severity, confidence, reason, observations, lambda _source, text: notes.append(text))


def _upload_correlation(detections: list[Detection], notes: list[str]) -> tuple[list[models.Finding], set[str]]:
    """``SAME_PATH`` dla pliku wykonywalnego w uploads i wykrycia z logu (zachowanie sprzed ADR 0007)."""
    # Atrybut ``path`` żądania jest po ``redact.neutralise``; ścieżka pliku przechodzi to samo, żeby nazwy ze znakami
    # sterującymi albo zmiany kierunku pisma (zapisane w raporcie jako U+FFFD) nadal się spotykały.
    uploads = {redact.neutralise(found.observation.location.path): found.observation for found in detections
               if found.rule == "EXECUTABLE_IN_UPLOADS" and found.observation.location.path is not None}
    findings, paths = [], set()
    for found in detections:
        if found.rule != "HTTP_EXECUTABLE_IN_UPLOADS":
            continue
        # ``path`` z parsera logów jest znormalizowany i nieredagowany; ``uri`` po redakcji może mieć zamaskowaną nazwę pliku.
        attributes = found.observation.attributes
        path = str(attributes.get("path") or str(attributes["uri"]).split("?")[0]).lstrip("/")
        if path in uploads:
            paths.add(path)
            findings.append(_finding(
                "CORRELATED_UPLOAD_REQUEST", "high", "medium",
                "Ten sam podejrzany plik występuje w obrazie witryny i w logu HTTP; to korelacja, nie dowód wykonania kodu.",
                (uploads[path].id, found.observation.id), notes))
    return findings, paths


def _flagged_files(detections: list[Detection], evidence: Mapping[str, models.Evidence]) -> list[_File]:
    """Pliki z ustaleniem plikowym, których dowodem jest plik kopii (nie wpis referencji), w kolejności ścieżek."""
    grouped: dict[str, tuple[int | None, set[str]]] = {}
    for found in detections:
        fact = found.observation
        record = evidence.get(fact.evidence_id)
        if found.category != "file" or record is None or record.origin_kind is not models.OriginKind.FILE or fact.location.path is None:
            continue
        mtime, ids = grouped.setdefault(fact.location.path, (record.mtime_ns, set()))
        ids.add(fact.id)
    return [_File(path, mtime, tuple(sorted(ids))) for path, (mtime, ids) in sorted(grouped.items())]


def _is_code(path: str) -> bool:
    return filerules.is_code(path) or filerules.is_double_extension_in_uploads(path)


def _uncertainty(request: models.Observation) -> int | None:
    """Zadeklarowana niepewność zegara; wartość innego typu albo ujemna nie poszerza okna."""
    value = request.attributes.get("clock_uncertainty_seconds")
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _ns(timestamp_utc: str) -> int:
    """Czas UTC z obserwacji jako nanosekundy od epoki, bez zaokrągleń zmiennoprzecinkowych."""
    return (datetime.fromisoformat(timestamp_utc) - _EPOCH) // _MICROSECOND * 1000


def _time_range(requests: list[models.Observation]) -> str:
    times = sorted(request.timestamp_utc for request in requests if request.timestamp_utc is not None)
    if not times:
        return "czas żądań nieznany"
    return f"zakres czasu żądań (UTC): {times[0]} – {times[-1]}"


def _same_path_reason(matched: list[models.Observation], shown: int) -> str:
    return (f"Żądania HTTP do tej samej ścieżki co plik kodu z ustaleniem plikowym (relacja SAME_PATH); żądań: {len(matched)}, "
            f"{_time_range(matched)}; w ustaleniu wskazano {shown}. {_NOT_CAUSAL} Plik mógł nie istnieć w chwili żądania, "
            "a konfiguracja serwera może kierować ten URL do innego pliku.")


def _near_reason(count: int, time_range: str, widened: int, shown: int, window: int) -> str:
    return (f"Żądania HTTP do plików kodu w oknie ±{window} s od mtime pliku z ustaleniem (relacja NEAR_IN_TIME); żądań: {count}, "
            f"{time_range}; okno poszerzone o zadeklarowaną niepewność zegara dla {widened}; w ustaleniu wskazano {shown}. "
            f"Bliskość w czasie może być przypadkowa. {_NOT_CAUSAL} mtime jest zmienialny (np. touch, rozpakowanie kopii), "
            "a zegar serwera logów mógł być przesunięty; relacja nie podnosi pewności ustalenia plikowego.")


def _capped(rule: str, findings: list[models.Finding], total: int, notes: list[str]) -> list[models.Finding]:
    """Ustalenia reguły do limitu; ``total`` to wszystkie wykrycia (ponad limit tylko liczone, bez budowania ustaleń)."""
    if total > MAX_FINDINGS_PER_RULE:
        notes.append(f"Limit {MAX_FINDINGS_PER_RULE} ustaleń reguły {rule} wyczerpany: wykryć było {total}; pozostałe pominięto")
    return findings[:MAX_FINDINGS_PER_RULE]


@dataclass
class _Clock:
    """Żądania z czasem UTC o tej samej zadeklarowanej niepewności zegara, posortowane po (czas, id).

    Okno ``NEAR_IN_TIME`` jest w nim przedziałem indeksów (bisect), a najbliższe żądania wybiera przejście od ``mtime``
    na zewnątrz po blokach równego czasu: koszt na plik nie zależy od liczby żądań w oknie (przegląd M6)."""
    uncertainty: int | None
    moments: list[int] = field(default_factory=list)
    requests: list[models.Observation] = field(default_factory=list)
    distinct: list[int] = field(default_factory=list)  # różne chwile, rosnąco
    starts: list[int] = field(default_factory=list)    # indeks pierwszego żądania każdej chwili; na końcu len(requests)
    ordered: bool = True  # czy tekstowy czas UTC rośnie razem z chwilą (wtedy zakres czasu to końce przedziału)

    def seal(self) -> None:
        for at, moment in enumerate(self.moments):
            if not self.distinct or self.distinct[-1] != moment:
                self.distinct.append(moment)
                self.starts.append(at)
        self.starts.append(len(self.moments))
        texts = [request.timestamp_utc for request in self.requests]
        self.ordered = all(left <= right for left, right in zip(texts, texts[1:]))

    def window(self, mtime: int, window_seconds: int) -> tuple[int, int]:
        reach = (window_seconds + (self.uncertainty or 0)) * 10**9
        return bisect.bisect_left(self.moments, mtime - reach), bisect.bisect_right(self.moments, mtime + reach)

    def span(self, lo: int, hi: int) -> tuple[str, str]:
        if self.ordered:
            return self.requests[lo].timestamp_utc, self.requests[hi - 1].timestamp_utc
        texts = [request.timestamp_utc for request in self.requests[lo:hi]]
        return min(texts), max(texts)

    def nearest(self, mtime: int, lo: int, hi: int, limit: int) -> list[tuple[int, int, str, models.Observation]]:
        """Do ``limit`` żądań z przedziału [lo, hi) w porządku (odległość od mtime, chwila, id)."""
        out: list = []
        right = bisect.bisect_left(self.distinct, mtime)
        left = right - 1
        while len(out) < limit:
            left_in = left >= 0 and self.starts[left] >= lo
            right_in = right < len(self.distinct) and self.starts[right] < hi
            if not (left_in or right_in):
                break
            if right_in and (not left_in or self.distinct[right] - mtime < mtime - self.distinct[left]):
                block, right = right, right + 1
            else:  # przy równej odległości pierwsza jest wcześniejsza chwila
                block, left = left, left - 1
            moment, first = self.distinct[block], self.starts[block]
            for request in self.requests[first:min(self.starts[block + 1], first + limit - len(out))]:
                out.append((abs(moment - mtime), moment, request.id, request))
        return out


def _clocks(usable: list[models.Observation]) -> list[_Clock]:
    grouped: dict[int | None, _Clock] = {}
    for moment, _, request in sorted((_ns(request.timestamp_utc), request.id, request) for request in usable
                                     if request.timestamp_utc is not None):
        uncertainty = _uncertainty(request)  # raz na żądanie
        clock = grouped.setdefault(uncertainty, _Clock(uncertainty))
        clock.moments.append(moment)
        clock.requests.append(request)
    for clock in grouped.values():
        clock.seal()
    return list(grouped.values())


def correlate(detections: list[Detection], requests: Iterable[models.Observation], evidence: Mapping[str, models.Evidence],
              window_seconds: int = DEFAULT_WINDOW_SECONDS, expired: Callable[[], bool] | None = None) -> Correlation:
    """Korelacje plik–żądanie: ``CORRELATED_UPLOAD_REQUEST``, ``CORRELATED_FILE_REQUEST`` i ``REQUEST_NEAR_FILE_CHANGE``.

    ``requests`` to obserwacje ``HTTP_REQUEST`` z atrybutem ``path`` (ADR 0007 pkt 7); inne rodzaje są pomijane.
    Jedno ustalenie na parę (plik, reguła) wskazuje obserwacje pliku i najwyżej ``MAX_REQUESTS_PER_FINDING`` żądań.
    ``NEAR_IN_TIME`` wymaga znanego czasu UTC żądania i ``mtime`` pliku; okno poszerza zadeklarowana niepewność zegara.
    Wynik nie zależy od kolejności wejścia. ``expired`` (limit czasu sesji) jest sprawdzany przed każdym plikiem;
    po jego upływie pozostałe pliki nie są korelowane, a nota (luka pokrycia logów) podaje, ile sprawdzono.
    """
    check_window(window_seconds)
    notes: list[str] = []
    uploads, upload_paths = _upload_correlation(detections, notes)
    usable = sorted((request for request in requests if request.kind == REQUEST_KIND and isinstance(request.attributes.get("path"), str)),
                    key=lambda request: (request.timestamp_utc or "", request.id))
    by_path: dict[str, list[models.Observation]] = {}
    for request in usable:
        by_path.setdefault(request.attributes["path"], []).append(request)
    clocks = _clocks(usable)
    same_path, near, referenced = [], [], {}
    same_total = near_total = 0
    flagged = _flagged_files(detections, evidence)

    for done, file in enumerate(flagged):
        if expired is not None and expired():
            notes.append(f"Limit czasu analizy przekroczony w trakcie korelacji: sprawdzono {done} z {len(flagged)} plików "
                         "z ustaleniem plikowym; pozostałych nie korelowano z logami")
            break
        shown_path = redact.neutralise(file.path)
        matched = by_path.get(shown_path, []) if _is_code(file.path) and shown_path not in upload_paths else []
        if matched:
            same_total += 1
            if same_total <= MAX_FINDINGS_PER_RULE:
                shown = matched[:MAX_REQUESTS_PER_FINDING]
                referenced.update((request.id, request) for request in shown)
                same_path.append(_finding("CORRELATED_FILE_REQUEST", "medium", "low", _same_path_reason(matched, len(shown)),
                                          file.observations + tuple(r.id for r in shown), notes))
        if file.mtime_ns is None:
            continue
        windows = [(clock, *clock.window(file.mtime_ns, window_seconds)) for clock in clocks]
        windows = [(clock, lo, hi) for clock, lo, hi in windows if hi > lo]
        if not windows:
            continue
        near_total += 1
        if near_total > MAX_FINDINGS_PER_RULE:
            continue  # ponad limit wykrycie jest tylko liczone
        candidates = sorted(item for clock, lo, hi in windows
                            for item in clock.nearest(file.mtime_ns, lo, hi, MAX_REQUESTS_PER_FINDING))
        shown = [request for *_, request in candidates[:MAX_REQUESTS_PER_FINDING]]
        referenced.update((request.id, request) for request in shown)
        spans = [clock.span(lo, hi) for clock, lo, hi in windows]
        count = sum(hi - lo for _, lo, hi in windows)
        widened = sum(hi - lo for clock, lo, hi in windows if clock.uncertainty is not None)
        time_range = f"zakres czasu żądań (UTC): {min(first for first, _ in spans)} – {max(last for _, last in spans)}"
        near.append(_finding("REQUEST_NEAR_FILE_CHANGE", "medium", "low",
                             _near_reason(count, time_range, widened, len(shown), window_seconds),
                             file.observations + tuple(r.id for r in shown), notes))

    findings = (uploads + _capped("CORRELATED_FILE_REQUEST", same_path, same_total, notes)
                + _capped("REQUEST_NEAR_FILE_CHANGE", near, near_total, notes))
    kept = {reference for finding in findings for reference in finding.observations}
    return Correlation(tuple(findings), tuple(request for key, request in sorted(referenced.items()) if key in kept), tuple(notes))


def _request_basis(request: models.Observation) -> str:
    uncertainty = _uncertainty(request)
    if uncertainty is None:
        return "HTTP access log; zegar niezweryfikowany, niepewność niezadeklarowana"
    return f"HTTP access log; niepewność zegara ±{uncertainty} s (deklaracja operatora, niezweryfikowana)"


def timeline(detections: list[Detection], evidence: dict[str, models.Evidence],
             requests: Iterable[models.Observation] = ()) -> tuple[list[models.TimelineEvent], list[str]]:
    """Oś czasu PoC oraz opisy plików, których mtime nie da się zapisać jako daty.

    ``requests`` to obserwacje żądań wskazane przez ustalenia korelacyjne (``Correlation.requests``); żądanie bez czasu UTC
    nie trafia na oś. Czas z logu zależy od zegara serwera, a mtime pliku jest zmienialny: żaden nie dowodzi czasu ataku.
    Zdarzenia są uporządkowane po czasie, a przy remisie po źródle, nazwie i identyfikatorach.
    """
    events, undated = [], []
    for found in detections:
        fact = found.observation
        if found.rule == "HTTP_EXECUTABLE_IN_UPLOADS" and fact.timestamp_utc is not None:
            events.append(models.TimelineEvent(
                fact.timestamp_utc, models.TimeSource.LOG, "HTTP access log; synchronizacja zegara niezweryfikowana", found.rule,
                models.describe_location(fact.location.to_dict()), "medium", fact.evidence_id, fact.id))
    # Ten sam wiersz logu bywa i wykryciem reguły uploads, i żądaniem korelacji: na osi czasu ma być raz.
    shown = {(found.observation.evidence_id, found.observation.location) for found in detections
             if found.rule == "HTTP_EXECUTABLE_IN_UPLOADS" and found.observation.timestamp_utc is not None}
    for request in requests:
        if request.timestamp_utc is not None and (request.evidence_id, request.location) not in shown:
            events.append(models.TimelineEvent(
                request.timestamp_utc, models.TimeSource.LOG, _request_basis(request), TIMELINE_EVENT,
                models.describe_location(request.location.to_dict()), "medium", request.evidence_id, request.id))
    flagged = {found.observation.evidence_id for found in detections if found.category == "file"}
    for item in evidence.values():
        if item.id in flagged and item.origin_kind is models.OriginKind.FILE and item.mtime_ns is not None:
            try:
                moment = models.utc_iso(datetime.fromtimestamp(item.mtime_ns / 1e9, tz=timezone.utc))
            except (ValueError, OverflowError, OSError):  # system plików może deklarować datę spoza zakresu datetime
                undated.append(f"Nie można zapisać mtime jako czasu UTC: {item.logical_path}")
                continue
            events.append(models.TimelineEvent(
                moment, models.TimeSource.MTIME, "Filesystem mtime: zmienialny; nie oznacza czasu ataku", "SUSPICIOUS_FILE_MTIME",
                item.logical_path, "low", item.id))
    events.sort(key=lambda event: (event.time_utc, event.source, event.event, event.evidence_id, event.observation_id or ""))
    return events, sorted(undated)
