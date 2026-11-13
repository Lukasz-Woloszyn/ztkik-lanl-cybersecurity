"""
Moduł 2: src/eda_baseline.py
Analiza czystego wycinka (EDA) oraz dobór realistycznych aktorów (użytkowników i komputerów)
do wstrzyknięcia ataków z zachowaniem pełnego kamuflażu OPSEC.
"""
import json
from pathlib import Path
from typing import Dict, Any
import numpy as np
import pandas as pd

from src.config import (
    CLEAN_SLICE_PATH,
    EDA_SUMMARY_PATH,
    AUTH_COLUMNS,
)


def load_auth_dataframe(csv_path: Path) -> pd.DataFrame:
    """Wczytuje plik CSV zgodny ze schematem LANL auth.txt (bez nagłówka)."""
    df = pd.read_csv(
        csv_path,
        names=AUTH_COLUMNS,
        header=None,
        dtype={
            "time": np.int64,
            "src_user": "string",
            "dst_user": "string",
            "src_computer": "string",
            "dst_computer": "string",
            "auth_type": "string",
            "logon_type": "string",
            "auth_orientation": "string",
            "status": "string",
        },
        na_filter=False,
    )
    return df


def run_eda_baseline(
    slice_path: Path = CLEAN_SLICE_PATH,
    output_summary_path: Path = EDA_SUMMARY_PATH,
) -> Dict[str, Any]:
    """
    Przeprowadza eksploracyjną analizę danych (EDA) na czystym wycinku auth_clean_slice.csv.
    Zwraca statystyki oraz wyselekcjonowane pule encji do symulacji ataków.
    """
    print(f"[EDA] Wczytywanie czystego wycinka: {slice_path}")
    df = load_auth_dataframe(slice_path)

    total_rows = len(df)
    t_min = int(df["time"].min())
    t_max = int(df["time"].max())
    duration_sec = t_max - t_min + 1

    # 1. Identyfikacja użytkowników ludzkich (U...@DOM1) posiadających >= 1 zdarzenie Success
    is_human_dst = df["dst_user"].str.startswith("U") & df["dst_user"].str.contains("@DOM1", regex=False)
    human_success_df = df[is_human_dst & (df["status"] == "Success")]

    user_event_counts = human_success_df["dst_user"].value_counts()
    valid_human_users = user_event_counts.index.tolist()

    # Wybieramy użytkowników o umiarkowanej, realistycznej aktywności (np. między 5 a 150 logowań),
    # aby nie wybierać kont całkowicie martwych ani kont super-administracyjnych.
    moderate_users = user_event_counts[(user_event_counts >= 5) & (user_event_counts <= 150)].index.tolist()
    if len(moderate_users) < 100:
        moderate_users = valid_human_users[:200]

    # Mapowanie typowego komputera źródłowego dla każdego użytkownika (do realistycznego C2 / Lateral Movement)
    human_net_df = human_success_df[human_success_df["src_computer"] != human_success_df["dst_computer"]]
    user_home_computer: Dict[str, str] = {}
    for user, grp in human_net_df.groupby("dst_user"):
        if len(grp) > 0:
            user_home_computer[str(user)] = str(grp["src_computer"].mode().iloc[0])

    # 2. Identyfikacja serwerów (wysoki in_degree unikalnych komputerów źródłowych) oraz stacji roboczych
    net_df = df[df["src_computer"] != df["dst_computer"]]
    in_degree = net_df.groupby("dst_computer")["src_computer"].nunique().sort_values(ascending=False)
    out_degree = net_df.groupby("src_computer")["dst_computer"].nunique().sort_values(ascending=False)

    # Top serwery (np. kontrolery domeny / serwery plików)
    top_servers = in_degree.head(25).index.tolist()

    # Aktywne stacje klienckie: umiarkowany out_degree (2..15) i niski in_degree (<= 5)
    all_computers = pd.Index(df["src_computer"].unique()).union(pd.Index(df["dst_computer"].unique()))
    client_candidates = []
    for comp in out_degree[(out_degree >= 2) & (out_degree <= 15)].index:
        if in_degree.get(comp, 0) <= 5 and str(comp).startswith("C"):
            client_candidates.append(str(comp))

    # Pula komputerów docelowych dla Lateral Movement (aktywne maszyny w sieci zaczynające się od C)
    dst_vc = df["dst_computer"].value_counts()
    active_computers = [
        str(c) for c, cnt in dst_vc.items() if str(c).startswith("C") and cnt >= 5
    ]

    # 3. Rozkład liczby zdarzeń w czasie (okna 1-minutowe i 5-minutowe)
    bucket_1m = (df["time"] - t_min) // 60
    events_1m = df.groupby(bucket_1m).size()
    fails_1m = df[df["status"] == "Fail"].groupby(bucket_1m).size().reindex(events_1m.index, fill_value=0)

    bucket_5m = (df["time"] - t_min) // 300
    events_5m = df.groupby(bucket_5m).size()
    fails_5m = df[df["status"] == "Fail"].groupby(bucket_5m).size().reindex(events_5m.index, fill_value=0)

    # Rozkład typów uwierzytelnień i statusów
    status_counts = df["status"].value_counts().to_dict()
    auth_type_counts = df["auth_type"].value_counts().to_dict()
    logon_type_counts = df["logon_type"].value_counts().to_dict()
    orientation_counts = df["auth_orientation"].value_counts().to_dict()

    summary = {
        "slice_path": str(slice_path),
        "total_rows": int(total_rows),
        "t_min": t_min,
        "t_max": t_max,
        "duration_seconds": int(duration_sec),
        "unique_src_users": int(df["src_user"].nunique()),
        "unique_dst_users": int(df["dst_user"].nunique()),
        "unique_human_users_with_success": len(valid_human_users),
        "unique_computers": int(len(all_computers)),
        "status_counts": {str(k): int(v) for k, v in status_counts.items()},
        "auth_type_counts": {str(k): int(v) for k, v in auth_type_counts.items()},
        "logon_type_counts": {str(k): int(v) for k, v in logon_type_counts.items()},
        "orientation_counts": {str(k): int(v) for k, v in orientation_counts.items()},
        "time_series_1m": {
            "num_windows": int(len(events_1m)),
            "mean_events_per_min": round(float(events_1m.mean()), 2),
            "std_events_per_min": round(float(events_1m.std()), 2),
            "median_events_per_min": round(float(events_1m.median()), 2),
            "mean_fails_per_min": round(float(fails_1m.mean()), 2),
            "max_fails_per_min": int(fails_1m.max()),
        },
        "time_series_5m": {
            "num_windows": int(len(events_5m)),
            "mean_events_per_5m": round(float(events_5m.mean()), 2),
            "std_events_per_5m": round(float(events_5m.std()), 2),
            "mean_fails_per_5m": round(float(fails_5m.mean()), 2),
            "max_fails_per_5m": int(fails_5m.max()),
        },
        "actor_pools": {
            "moderate_human_users": [str(u) for u in moderate_users[:250]],
            "top_servers": [str(c) for c in top_servers],
            "top_servers_in_degree": {str(k): int(v) for k, v in in_degree.head(15).items()},
            "client_computers": client_candidates[:200],
            "active_computers": [str(c) for c in active_computers[:500]],
            "user_home_computer": user_home_computer,
        },
    }

    output_summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(
        f"[EDA] Przeanalizowano {total_rows:,} wierszy | "
        f"Aktywni użytkownicy ludzcy (Success): {len(valid_human_users):,} | "
        f"Unikalne komputery: {len(all_computers):,} | "
        f"Top serwer: {top_servers[0]} (in_degree={in_degree.iloc[0]})"
    )
    return summary


if __name__ == "__main__":
    run_eda_baseline()
