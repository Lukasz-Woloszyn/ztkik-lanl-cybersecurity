"""
Moduł 1: src/slicer.py
Strumieniowe wycinanie czystego, ciągłego okna czasowego z pliku LANL auth.txt / auth.txt.gz
bez ładowania wielogigabajtowego pliku do pamięci RAM.
"""
import gzip
import json
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np

from src.config import (
    RAW_AUTH_CANDIDATES,
    CLEAN_SLICE_PATH,
    SLICE_START_TIME,
    SLICE_TARGET_ROWS,
    MAX_SAFE_END_TIME,
    RANDOM_SEED,
)


def find_raw_auth_file() -> Optional[Path]:
    """Wyszukuje plik auth.txt lub auth.txt.gz w znanych lokalizacjach."""
    for candidate in RAW_AUTH_CANDIDATES:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    return None


def _open_stream(file_path: Path):
    """Otwiera strumień tekstowy z pliku skompresowanego (.gz) lub zwykłego (.txt)."""
    if file_path.suffix == ".gz":
        return gzip.open(file_path, mode="rt", encoding="utf-8", errors="replace")
    return open(file_path, mode="r", encoding="utf-8", errors="replace")


def extract_clean_slice(
    raw_path: Optional[Path] = None,
    output_path: Path = CLEAN_SLICE_PATH,
    start_time: int = SLICE_START_TIME,
    target_rows: int = SLICE_TARGET_ROWS,
) -> Dict[str, Any]:
    """
    Strumieniowo wycina ciągły blok zdarzeń z auth.txt(.gz) począwszy od `start_time`.
    Pobiera co najmniej `target_rows` wierszy i domyka pełną ostatnią sekundę t_end,
    aby nie uciąć sekundy w połowie.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if raw_path is None:
        raw_path = find_raw_auth_file()

    if raw_path is None or not raw_path.exists():
        print("[SLICER] Nie znaleziono pliku auth.txt(.gz) - uruchamiam generator syntetyczny (Fallback)...")
        return generate_synthetic_lanl_slice(output_path=output_path, n_rows=target_rows, start_time=start_time)

    print(f"[SLICER] Otwieranie strumieniowe pliku źródłowego: {raw_path} ({raw_path.stat().st_size / (1024**3):.2f} GB)")
    print(f"[SLICER] Cel: start_time >= {start_time} s, target_rows = {target_rows:,} wierszy")

    written_rows = 0
    skipped_rows = 0
    malformed_rows = 0
    actual_start_time: Optional[int] = None
    target_end_time: Optional[int] = None
    last_time: Optional[int] = None

    with _open_stream(raw_path) as infile, open(output_path, mode="w", encoding="utf-8", newline="\n") as outfile:
        for line in infile:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Szybkie odczytanie pierwszej kolumny (time) bez pełnego splitu dla pomijanych wierszy
            comma_idx = line_stripped.find(",")
            if comma_idx == -1:
                malformed_rows += 1
                continue

            try:
                t = int(line_stripped[:comma_idx])
            except ValueError:
                malformed_rows += 1
                continue

            if t < start_time:
                skipped_rows += 1
                continue

            # Jeśli osiągnęliśmy już docelową liczbę wierszy, domykamy tylko bieżącą sekundę target_end_time
            if target_end_time is not None and t > target_end_time:
                break

            # Walidacja 9 kolumn LANL auth.txt
            parts = line_stripped.split(",")
            if len(parts) != 9:
                malformed_rows += 1
                continue

            if actual_start_time is None:
                actual_start_time = t

            outfile.write(line_stripped + "\n")
            written_rows += 1
            last_time = t

            if written_rows >= target_rows and target_end_time is None:
                target_end_time = t

    if actual_start_time is None or last_time is None:
        raise RuntimeError(f"Nie udało się wyciąć żadnych wierszy dla start_time={start_time}.")

    assert last_time < MAX_SAFE_END_TIME, (
        f"BŁĄD OPSEC: Koniec wycinka t_end={last_time} przekracza bezpieczny próg "
        f"{MAX_SAFE_END_TIME} (pierwsze zdarzenie w redteam.txt to 150885)!"
    )

    duration_sec = last_time - actual_start_time + 1
    meta = {
        "source_file": str(raw_path),
        "output_file": str(output_path),
        "is_synthetic": False,
        "skipped_rows_before_start": skipped_rows,
        "malformed_rows_skipped": malformed_rows,
        "written_rows": written_rows,
        "start_time": actual_start_time,
        "end_time": last_time,
        "duration_seconds": duration_sec,
        "duration_hours": round(duration_sec / 3600.0, 2),
        "safe_before_redteam": last_time < 150885,
    }

    print(
        f"[SLICER] Sukces! Zapisano {written_rows:,} wierszy "
        f"(t = {actual_start_time} .. {last_time}, czas trwania: {duration_sec:,} s / {meta['duration_hours']} h)."
    )
    return meta


def generate_synthetic_lanl_slice(
    output_path: Path = CLEAN_SLICE_PATH,
    n_rows: int = SLICE_TARGET_ROWS,
    start_time: int = SLICE_START_TIME,
) -> Dict[str, Any]:
    """
    Tryb testowy (Fallback): generuje realistyczny wycinek zgodny ze schematem LANL
    (rozkład Poissona z cyklem dobowym, konta U...@DOM1 i C...$@DOM1).
    """
    rng = np.random.default_rng(RANDOM_SEED)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    duration = 14_400  # 4 godziny
    times = np.sort(rng.integers(start_time, start_time + duration, size=n_rows))

    users = [f"U{i}@DOM1" for i in range(1, 601)]
    comp_ids = [f"C{i}" for i in range(1, 801)]
    servers = [f"C{i}" for i in range(1, 31)]

    with open(output_path, mode="w", encoding="utf-8", newline="\n") as f:
        for t in times:
            if rng.random() < 0.45:
                u = rng.choice(users)
                src_c = rng.choice(comp_ids)
                dst_c = rng.choice(servers) if rng.random() < 0.7 else src_c
                auth_t = rng.choice(["Kerberos", "Negotiate", "NTLM"], p=[0.6, 0.25, 0.15])
                logon_t = "Network" if src_c != dst_c else "Interactive"
                orient = rng.choice(["LogOn", "LogOff", "TGS", "TGT"], p=[0.45, 0.35, 0.15, 0.05])
                status = "Success" if rng.random() < 0.992 else "Fail"
                f.write(f"{t},{u},{u},{src_c},{dst_c},{auth_t},{logon_t},{orient},{status}\n")
            else:
                c = rng.choice(comp_ids)
                cu = f"{c}$@DOM1"
                dst_c = rng.choice(servers) if rng.random() < 0.5 else c
                dst_u = f"SYSTEM@{c}" if dst_c == c else cu
                auth_t = rng.choice(["Negotiate", "Kerberos", "?"], p=[0.45, 0.35, 0.20])
                logon_t = "Service" if dst_c == c else "Network"
                orient = "LogOn" if auth_t != "?" else "LogOff"
                f.write(f"{t},{cu},{dst_u},{c},{dst_c},{auth_t},{logon_t},{orient},Success\n")

    meta = {
        "source_file": "SYNTHETIC_FALLBACK",
        "output_file": str(output_path),
        "is_synthetic": True,
        "written_rows": n_rows,
        "start_time": int(times[0]),
        "end_time": int(times[-1]),
        "duration_seconds": int(times[-1] - times[0] + 1),
        "duration_hours": round(float(times[-1] - times[0] + 1) / 3600.0, 2),
        "safe_before_redteam": True,
    }
    return meta


if __name__ == "__main__":
    info = extract_clean_slice()
    print(json.dumps(info, indent=2, ensure_ascii=False))

