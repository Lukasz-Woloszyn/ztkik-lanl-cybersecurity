"""
Moduł 3: src/attack_injector.py
Generator 3 zaawansowanych scenariuszy ataków cybernetycznych (Password Spraying, C2 Beaconing,
Lateral Movement) z zachowaniem pełnego kamuflażu OPSEC, scalaniem, sortowaniem mergesort
oraz generowaniem tajnego manifestu Ground Truth.
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

from src.config import (
    CLEAN_SLICE_PATH,
    EDA_SUMMARY_PATH,
    MODIFIED_AUTH_PATH,
    MANIFEST_PATH,
    AUTH_COLUMNS,
    ATTACK_CONFIG,
    RANDOM_SEED,
)
from src.eda_baseline import load_auth_dataframe, run_eda_baseline


def inject_password_spraying(
    df_clean: pd.DataFrame,
    eda_info: Dict[str, Any],
    rng: np.random.Generator,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Atak 1: Password Spraying (Rozpylanie haseł).
    - 1 komputer źródłowy C_src, 1 serwer docelowy C_srv, N = 60 istniejących użytkowników U_i@DOM1.
    - W oknie <= 600 s generuje po 3 nieudane próby (Kerberos, Network, LogOn, Fail) dla każdego z 60
      użytkowników z odstępami między kolejnymi kontami z rozkładu normalnego N(3, 1),
      a dla 2 wybranych użytkowników kończy logowaniem udanym (Success).
    """
    cfg = ATTACK_CONFIG["password_spraying"]
    n_users = cfg["n_target_users"]
    fails_per_user = cfg["fails_per_user"]
    n_comp = cfg["n_compromised"]

    t_min = int(eda_info["t_min"])
    t_max = int(eda_info["t_max"])

    # Wybieramy początek okna dokładnie na granicy okna 5-minutowego (np. t_min + 1800 = 16800),
    # aby pik w oknie 5-minutowym i oknach 1-minutowych był maksymalnie wyrazisty statystycznie.
    spray_start = t_min + 1800
    if spray_start + cfg["window_seconds"] > t_max:
        spray_start = t_min + 300

    # Wybór komputera atakującego (aktywna stacja robocza) i serwera docelowego (kontroler domeny)
    client_pool = eda_info["actor_pools"]["client_computers"]
    server_pool = eda_info["actor_pools"]["top_servers"]
    c_src = str(client_pool[5]) if len(client_pool) > 5 else str(client_pool[0])
    c_srv = str(server_pool[0])  # Główny serwer / DC (np. C586)

    # Wybór 60 użytkowników posiadających co najmniej 1 zdarzenie Success w wycinku (wymóg LANL dla Fail)
    user_pool = eda_info["actor_pools"]["moderate_human_users"]
    target_users = [str(u) for u in user_pool[:n_users]]
    compromised_users = [target_users[10], target_users[25]]

    rows: List[Dict[str, Any]] = []
    current_t = float(spray_start)
    iat_samples: List[float] = []

    # Przejście po 60 użytkownikach z krokiem Delta_t ~ N(3, 1) s (3 próby haseł na każdego użytkownika)
    for idx, user in enumerate(target_users):
        if idx > 0:
            dt = float(rng.normal(loc=cfg["iat_mean"], scale=cfg["iat_std"]))
            dt = max(1.0, round(dt))
            iat_samples.append(dt)
            current_t += dt

        base_sec = int(round(current_t))
        for attempt in range(fails_per_user):
            t_attempt = min(t_max, base_sec + (attempt // 2))
            rows.append(
                {
                    "time": t_attempt,
                    "src_user": user,
                    "dst_user": user,
                    "src_computer": c_src,
                    "dst_computer": c_srv,
                    "auth_type": cfg["auth_type"],
                    "logon_type": cfg["logon_type"],
                    "auth_orientation": cfg["auth_orientation"],
                    "status": "Fail",
                }
            )

        # Dla 2 przejętych użytkowników ostatnia próba (czwarta) kończy się sukcesem (odgadnięcie hasła!)
        if user in compromised_users:
            t_succ = min(t_max, base_sec + 2)
            rows.append(
                {
                    "time": t_succ,
                    "src_user": user,
                    "dst_user": user,
                    "src_computer": c_src,
                    "dst_computer": c_srv,
                    "auth_type": cfg["auth_type"],
                    "logon_type": cfg["logon_type"],
                    "auth_orientation": "LogOn",
                    "status": "Success",
                }
            )
            rows.append(
                {
                    "time": min(t_max, t_succ + 2),
                    "src_user": user,
                    "dst_user": user,
                    "src_computer": c_srv,
                    "dst_computer": c_srv,
                    "auth_type": "?",
                    "logon_type": "Network",
                    "auth_orientation": "LogOff",
                    "status": "Success",
                }
            )

    spray_end = max(r["time"] for r in rows)
    meta = {
        "attack_name": "Password Spraying",
        "src_computer": c_src,
        "dst_computer": c_srv,
        "n_target_users": len(target_users),
        "target_users": target_users,
        "compromised_users": compromised_users,
        "start_time": int(spray_start),
        "end_time": int(spray_end),
        "duration_seconds": int(spray_end - spray_start),
        "fails_per_user": fails_per_user,
        "total_fail_events": n_users * fails_per_user,
        "total_success_events": len(compromised_users) * 2,
        "total_injected_rows": len(rows),
        "iat_mean_actual": round(float(np.mean(iat_samples)), 3),
        "iat_std_actual": round(float(np.std(iat_samples)), 3),
    }
    return rows, meta


def inject_c2_beaconing(
    df_clean: pd.DataFrame,
    eda_info: Dict[str, Any],
    compromised_user: str,
    rng: np.random.Generator,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Atak 2: C2 Beaconing (Ukryty Bot Uwierzytelniający).
    - Wybiera 1 przejętego użytkownika U_bot@DOM1, jego komputer C_bot oraz docelowy serwer C_c2.
    - Przez cały czas trwania wycinka wstawia cykliczne uwierzytelnienia sieciowe
      (NTLM, Network, LogOn, Success) w chwilach:
      t_k = t_start + k * T + epsilon_k, T = 90 s, epsilon_k in {-2, -1, 0, 1, 2}.
    """
    cfg = ATTACK_CONFIG["c2_beaconing"]
    period = cfg["period_seconds"]
    jitter_choices = cfg["jitter_choices"]

    t_min = int(eda_info["t_min"])
    t_max = int(eda_info["t_max"])

    home_map = eda_info["actor_pools"]["user_home_computer"]
    client_pool = eda_info["actor_pools"]["client_computers"]
    server_pool = eda_info["actor_pools"]["top_servers"]

    c_bot = home_map.get(compromised_user, str(client_pool[12]))

    # Wybieramy serwer docelowy C_c2, z którym użytkownik U_bot@DOM1 nie miał wcześniej połączeń w wycinku,
    # aby szereg IAT dla pary (U_bot, C_c2) był w 100% czysty od szumu tła.
    existing_dsts = set(
        df_clean[df_clean["src_user"] == compromised_user]["dst_computer"].unique().tolist()
    )
    c_c2 = None
    for srv in server_pool[2:]:
        if srv not in existing_dsts and srv != c_bot:
            c_c2 = str(srv)
            break
    if c_c2 is None:
        c_c2 = str(server_pool[-1])

    rows: List[Dict[str, Any]] = []
    beacon_times: List[int] = []

    t_start_beacon = t_min + 15
    k = 0
    while True:
        jitter = int(rng.choice(jitter_choices))
        t_k = t_start_beacon + k * period + jitter
        if t_k > t_max - 3:
            break
        t_k = max(t_min, t_k)
        beacon_times.append(t_k)

        rows.append(
            {
                "time": t_k,
                "src_user": compromised_user,
                "dst_user": compromised_user,
                "src_computer": c_bot,
                "dst_computer": c_c2,
                "auth_type": cfg["auth_type"],
                "logon_type": cfg["logon_type"],
                "auth_orientation": "LogOn",
                "status": "Success",
            }
        )

        if cfg.get("include_logoff", True):
            delay = int(rng.integers(cfg["logoff_delay_range"][0], cfg["logoff_delay_range"][1] + 1))
            rows.append(
                {
                    "time": min(t_max, t_k + delay),
                    "src_user": compromised_user,
                    "dst_user": compromised_user,
                    "src_computer": c_c2,
                    "dst_computer": c_c2,
                    "auth_type": "?",
                    "logon_type": "Network",
                    "auth_orientation": "LogOff",
                    "status": "Success",
                }
            )
        k += 1

    iats = np.diff(beacon_times)
    cv = float(np.std(iats) / np.mean(iats))

    meta = {
        "attack_name": "C2 Beaconing",
        "src_user": compromised_user,
        "src_computer": c_bot,
        "dst_computer": c_c2,
        "period_seconds": period,
        "jitter_choices": jitter_choices,
        "start_time": int(beacon_times[0]),
        "end_time": int(beacon_times[-1]),
        "num_beacons_logon": len(beacon_times),
        "total_injected_rows": len(rows),
        "iat_mean_actual": round(float(np.mean(iats)), 3),
        "iat_std_actual": round(float(np.std(iats)), 3),
        "iat_cv_actual": round(cv, 5),
    }
    return rows, meta


def inject_lateral_movement(
    df_clean: pd.DataFrame,
    eda_info: Dict[str, Any],
    compromised_user: str,
    rng: np.random.Generator,
    avoid_computers: List[str],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Atak 3: Lateral Movement (Ruch boczny w sieci / Skanowanie SMB).
    - Wybiera 1 przejętego użytkownika U_lat@DOM1.
    - W oknie 1800 s (30 minut) tworzy kaskadę logowań:
      najpierw łańcuch C_1 -> C_2 -> C_3 -> C_4, a następnie z C_4 serię logowań
      (Negotiate, Network, LogOn, Success) na 35 różnych komputerów docelowych,
      na które to konto nigdy wcześniej się nie logowało.
    """
    cfg = ATTACK_CONFIG["lateral_movement"]
    t_min = int(eda_info["t_min"])
    t_max = int(eda_info["t_max"])

    # Rozpoczynamy ruch boczny tuż po zakończeniu Password Spraying (np. t_min + 2200)
    lat_start = t_min + 2200
    lat_window = min(cfg["window_seconds"], t_max - lat_start - 30)

    # Komputery, na które U_lat@DOM1 kiedykolwiek logował się w czystym wycinku
    prior_computers = set(
        df_clean[
            (df_clean["src_user"] == compromised_user) | (df_clean["dst_user"] == compromised_user)
        ]["dst_computer"]
        .unique()
        .tolist()
    )
    excluded = prior_computers.union(set(avoid_computers)).union({"?"})

    home_map = eda_info["actor_pools"]["user_home_computer"]
    client_pool = eda_info["actor_pools"]["client_computers"]
    active_pool = eda_info["actor_pools"]["active_computers"]

    c_1 = home_map.get(compromised_user, str(client_pool[20]))
    excluded.add(c_1)

    # Budowa łańcucha C_1 -> C_2 -> C_3 -> C_4
    hop_candidates = [c for c in client_pool if c not in excluded]
    c_2, c_3, c_4 = str(hop_candidates[0]), str(hop_candidates[1]), str(hop_candidates[2])
    excluded.update([c_2, c_3, c_4])
    chain_hops = [c_1, c_2, c_3, c_4]

    # Wybór 35 unikalnych komputerów docelowych z C_4, na które konto nigdy wcześniej się nie logowało
    fanout_candidates = [str(c) for c in active_pool if str(c) not in excluded]
    n_fanout = cfg["n_fanout_targets"]
    fanout_targets = fanout_candidates[:n_fanout]

    rows: List[Dict[str, Any]] = []
    current_t = lat_start

    # Etap A: Kaskada wieloskokowa C_1 -> C_2 -> C_3 -> C_4
    chain_edges = [(c_1, c_2), (c_2, c_3), (c_3, c_4)]
    for src_c, dst_c in chain_edges:
        for rep in range(3):
            t_ev = current_t + rep * 4
            rows.append(
                {
                    "time": t_ev,
                    "src_user": compromised_user,
                    "dst_user": compromised_user,
                    "src_computer": src_c,
                    "dst_computer": dst_c,
                    "auth_type": cfg["auth_type"],
                    "logon_type": cfg["logon_type"],
                    "auth_orientation": "LogOn",
                    "status": "Success",
                }
            )
            rows.append(
                {
                    "time": t_ev + 2,
                    "src_user": compromised_user,
                    "dst_user": compromised_user,
                    "src_computer": dst_c,
                    "dst_computer": dst_c,
                    "auth_type": "?",
                    "logon_type": "Network",
                    "auth_orientation": "LogOff",
                    "status": "Success",
                }
            )
        current_t += int(rng.integers(25, 45))

    # Etap B: Fan-out z C_4 na 35 różnych komputerów docelowych w oknie 1800 s
    remaining_window = max(600, (lat_start + lat_window) - current_t)
    step_per_target = max(8, remaining_window // max(1, len(fanout_targets)))
    attempts_per_target = cfg.get("attempts_per_target", 4)

    for idx, dst_c in enumerate(fanout_targets):
        base_t = current_t + idx * step_per_target + int(rng.integers(-3, 4))
        base_t = min(t_max - 10, max(current_t, base_t))
        for rep in range(attempts_per_target):
            t_ev = min(t_max - 2, base_t + rep * 2)
            rows.append(
                {
                    "time": t_ev,
                    "src_user": compromised_user,
                    "dst_user": compromised_user,
                    "src_computer": c_4,
                    "dst_computer": dst_c,
                    "auth_type": cfg["auth_type"],
                    "logon_type": cfg["logon_type"],
                    "auth_orientation": "LogOn",
                    "status": "Success",
                }
            )
            rows.append(
                {
                    "time": min(t_max, t_ev + 1),
                    "src_user": compromised_user,
                    "dst_user": compromised_user,
                    "src_computer": dst_c,
                    "dst_computer": dst_c,
                    "auth_type": "?",
                    "logon_type": "Network",
                    "auth_orientation": "LogOff",
                    "status": "Success",
                }
            )

    lat_end = max(r["time"] for r in rows)
    meta = {
        "attack_name": "Lateral Movement",
        "src_user": compromised_user,
        "chain_hops": chain_hops,
        "pivot_computer": c_4,
        "n_fanout_targets": len(fanout_targets),
        "fanout_targets": fanout_targets,
        "total_new_unique_computers": len(set(chain_hops[1:] + fanout_targets)),
        "start_time": int(lat_start),
        "end_time": int(lat_end),
        "duration_seconds": int(lat_end - lat_start),
        "total_injected_rows": len(rows),
    }
    return rows, meta


def verify_opsec(
    df_clean: pd.DataFrame,
    df_modified: pd.DataFrame,
    injected_fail_users: List[str],
) -> Dict[str, Any]:
    """
    Automatyczna kontrola zasad kamuflażu OPSEC na wygenerowanym zbiorze.
    """
    # 1. Sprawdzenie monotoniczności czasu (posortowanie rosnące)
    is_sorted = bool(df_modified["time"].is_monotonic_increasing)

    # 2. Sprawdzenie zasady Fail w LANL dla wstrzykniętych ofiar:
    # każdy wstrzyknięty użytkownik ze statusem Fail musi mieć >= 1 zdarzenie Success w wycinku bazowym
    users_with_success = set(df_clean[df_clean["status"] == "Success"]["dst_user"].unique())
    injected_fail_without_success = set(injected_fail_users) - users_with_success

    # 3. Sprawdzenie, czy wszystkie identyfikatory użytkowników i komputerów pochodzą z oryginalnego wycinka
    orig_users = set(df_clean["src_user"].unique()).union(set(df_clean["dst_user"].unique()))
    mod_users = set(df_modified["src_user"].unique()).union(set(df_modified["dst_user"].unique()))
    new_synthetic_users = mod_users - orig_users

    orig_comps = set(df_clean["src_computer"].unique()).union(set(df_clean["dst_computer"].unique()))
    mod_comps = set(df_modified["src_computer"].unique()).union(set(df_modified["dst_computer"].unique()))
    new_synthetic_comps = mod_comps - orig_comps

    checks = {
        "is_time_sorted_monotonic": is_sorted,
        "num_columns": int(df_modified.shape[1]),
        "injected_fail_users_without_success": len(injected_fail_without_success),
        "unknown_synthetic_users_count": len(new_synthetic_users),
        "unknown_synthetic_computers_count": len(new_synthetic_comps),
        "all_checks_passed": (
            is_sorted
            and df_modified.shape[1] == 9
            and len(injected_fail_without_success) == 0
            and len(new_synthetic_users) == 0
            and len(new_synthetic_comps) == 0
        ),
    }
    if not checks["all_checks_passed"]:
        raise AssertionError(f"Naruszenie zasad OPSEC: {checks}")
    return checks


def run_injection_pipeline(
    clean_slice_path: Path = CLEAN_SLICE_PATH,
    eda_summary_path: Path = EDA_SUMMARY_PATH,
    modified_output_path: Path = MODIFIED_AUTH_PATH,
    manifest_output_path: Path = MANIFEST_PATH,
) -> Dict[str, Any]:
    """
    Główny potok wstrzykiwania ataków:
    1. Wczytuje czysty wycinek i wyniki EDA.
    2. Generuje 3 powiązane logicznie ataki (Password Spraying -> C2 Beaconing + Lateral Movement).
    3. Scala wiersze, sortuje stabilnie (`mergesort`) po kolumnie `time`.
    4. Weryfikuje reguły OPSEC i zapisuje plik wynikowy bez nagłówka oraz `manifest.json`.
    """
    rng = np.random.default_rng(RANDOM_SEED)

    if not eda_summary_path.exists():
        eda_info = run_eda_baseline(clean_slice_path, eda_summary_path)
    else:
        with open(eda_summary_path, "r", encoding="utf-8") as f:
            eda_info = json.load(f)

    print(f"[INJECTOR] Wczytywanie czystego wycinka z: {clean_slice_path}")
    df_clean = load_auth_dataframe(clean_slice_path)

    # 1. Generowanie Ataku 1: Password Spraying
    spray_rows, spray_meta = inject_password_spraying(df_clean, eda_info, rng)
    u_bot, u_lat = spray_meta["compromised_users"][0], spray_meta["compromised_users"][1]

    # 2. Generowanie Ataku 2: C2 Beaconing (na pierwszym przejętym koncie u_bot)
    c2_rows, c2_meta = inject_c2_beaconing(df_clean, eda_info, u_bot, rng)

    # 3. Generowanie Ataku 3: Lateral Movement (na drugim przejętym koncie u_lat)
    avoid_comps = [spray_meta["src_computer"], spray_meta["dst_computer"], c2_meta["src_computer"], c2_meta["dst_computer"]]
    lat_rows, lat_meta = inject_lateral_movement(df_clean, eda_info, u_lat, rng, avoid_comps)

    all_injected_rows = spray_rows + c2_rows + lat_rows
    df_injected = pd.DataFrame(all_injected_rows, columns=AUTH_COLUMNS)

    # Oznaczamy pomocniczą flagą przed sortowaniem, aby zapisać w manifeście dokładne indeksy wierszy
    df_clean_tagged = df_clean.copy()
    df_clean_tagged["_attack_tag"] = ""

    tag_list = (
        ["password_spraying"] * len(spray_rows)
        + ["c2_beaconing"] * len(c2_rows)
        + ["lateral_movement"] * len(lat_rows)
    )
    df_injected["_attack_tag"] = tag_list

    df_combined = pd.concat([df_clean_tagged, df_injected], ignore_index=True)

    # Sortowanie stabilne po kolumnie time rosnąco (kind='mergesort')
    df_combined["time"] = df_combined["time"].astype(np.int64)
    df_combined = df_combined.sort_values(by="time", kind="mergesort").reset_index(drop=True)

    # Wyciągnięcie dokładnych indeksów wierszy w posortowanym pliku wynikowym
    spray_indices = df_combined.index[df_combined["_attack_tag"] == "password_spraying"].tolist()
    c2_indices = df_combined.index[df_combined["_attack_tag"] == "c2_beaconing"].tolist()
    lat_indices = df_combined.index[df_combined["_attack_tag"] == "lateral_movement"].tolist()

    df_final = df_combined[AUTH_COLUMNS]

    # Weryfikacja OPSEC
    opsec_report = verify_opsec(df_clean, df_final, spray_meta["target_users"])
    print(f"[INJECTOR] Weryfikacja OPSEC zakończona pomyślnie: {opsec_report}")

    # Zapis zmodyfikowanego pliku CSV bez nagłówka z końcami linii \n
    modified_output_path.parent.mkdir(parents=True, exist_ok=True)
    df_final.to_csv(
        modified_output_path,
        index=False,
        header=False,
        lineterminator="\n",
    )

    spray_meta["injected_row_indices_sample"] = spray_indices[:15]
    spray_meta["injected_row_index_range"] = [int(min(spray_indices)), int(max(spray_indices))]
    c2_meta["injected_row_indices_sample"] = c2_indices[:15]
    c2_meta["injected_row_index_range"] = [int(min(c2_indices)), int(max(c2_indices))]
    lat_meta["injected_row_indices_sample"] = lat_indices[:15]
    lat_meta["injected_row_index_range"] = [int(min(lat_indices)), int(max(lat_indices))]

    manifest = {
        "project": "ZTKIK - LANL Cyber1 Red Team Attack Simulation",
        "clean_slice_rows": int(len(df_clean)),
        "total_injected_rows": int(len(df_injected)),
        "modified_total_rows": int(len(df_final)),
        "injection_ratio_percent": round(100.0 * len(df_injected) / len(df_final), 4),
        "time_range": {
            "t_min": int(df_final["time"].min()),
            "t_max": int(df_final["time"].max()),
            "duration_seconds": int(df_final["time"].max() - df_final["time"].min() + 1),
        },
        "opsec_verification": opsec_report,
        "attacks": {
            "attack_1_password_spraying": spray_meta,
            "attack_2_c2_beaconing": c2_meta,
            "attack_3_lateral_movement": lat_meta,
        },
    }

    manifest_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(
        f"[INJECTOR] Zapisano zmodyfikowany zbiór: {modified_output_path} "
        f"({len(df_final):,} wierszy, w tym {len(df_injected):,} wstrzykniętych = {manifest['injection_ratio_percent']}%)."
    )
    print(f"[INJECTOR] Zapisano tajny manifest: {manifest_output_path}")
    return manifest


if __name__ == "__main__":
    run_injection_pipeline()
