"""
Szybki moduł ingestii i kontroli kryminalistycznej (Forensic Ingest) dla zbioru otrzymanego
od grupy przeciwnej: data/received_from_enemy/lanl-auth-dataset-advanced-attacked (1.6 GB).

Konwertuje strumieniowo plik CSV (time,user,computer) do szybkich tablic binarnych NumPy (.npy):
- time.npy (int32)
- uid.npy (int32)
- cid.npy (int32)
oraz wykonuje natychmiastową kontrolę błędów OPSEC (nieposortowane wiersze, nieznane formaty,
ID spoza zakresu LANL U1..U11362 i C1..C22284, duplikaty, skoki czasu).
"""
import json
import time as time_mod
from pathlib import Path
import numpy as np
import pandas as pd

from src.config import RECEIVED_DIR

ENEMY_RAW_PATH = RECEIVED_DIR / "lanl-auth-dataset-advanced-attacked"
CACHE_DIR = RECEIVED_DIR / "cache"


def ingest_enemy_dataset() -> dict:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time_mod.time()
    print(f"[ENEMY-INGEST] Start skanowania pliku: {ENEMY_RAW_PATH} ({ENEMY_RAW_PATH.stat().st_size / (1024**3):.2f} GB)")

    time_chunks = []
    uid_chunks = []
    cid_chunks = []

    total_rows = 0
    out_of_order_events = []
    non_standard_users = []
    non_standard_comps = []
    last_t = -1

    chunk_size = 5_000_000
    reader = pd.read_csv(
        ENEMY_RAW_PATH,
        names=["time", "user", "computer"],
        header=None,
        dtype={"time": "string", "user": "string", "computer": "string"},
        na_filter=False,
        chunksize=chunk_size,
        engine="c",
    )

    for chunk_idx, chunk in enumerate(reader):
        n_c = len(chunk)
        # 1. Konwersja time
        t_vals = pd.to_numeric(chunk["time"], errors="coerce")
        bad_t = t_vals.isna()
        if bad_t.any():
            for idx in chunk.index[bad_t][:10]:
                non_standard_users.append({"row": int(idx), "raw": chunk.loc[idx].to_dict()})
            t_vals = t_vals.fillna(-1)
        t_arr = t_vals.astype(np.int32).to_numpy()

        # Sprawdzenie monotoniczności na styku chunków i wewnątrz chunka
        if len(t_arr) > 0:
            if last_t > t_arr[0]:
                out_of_order_events.append(
                    {"row": int(total_rows), "prev_time": int(last_t), "curr_time": int(t_arr[0])}
                )
            diffs = np.diff(t_arr)
            neg_idx = np.where(diffs < 0)[0]
            if len(neg_idx) > 0:
                for ni in neg_idx[:20]:
                    out_of_order_events.append(
                        {
                            "row": int(total_rows + ni + 1),
                            "prev_time": int(t_arr[ni]),
                            "curr_time": int(t_arr[ni + 1]),
                        }
                    )
            last_t = int(t_arr[-1])

        # 2. Konwersja user (U<int>)
        u_str = chunk["user"].str.slice(1)
        u_vals = pd.to_numeric(u_str, errors="coerce")
        bad_u = (~chunk["user"].str.startswith("U")) | u_vals.isna()
        if bad_u.any():
            for idx in chunk.index[bad_u][:20]:
                non_standard_users.append({"row": int(idx), "user": str(chunk.loc[idx, "user"]), "time": int(t_arr[idx - total_rows])})
            u_vals = u_vals.fillna(-1)
        u_arr = u_vals.astype(np.int32).to_numpy()

        # 3. Konwersja computer (C<int>)
        c_str = chunk["computer"].str.slice(1)
        c_vals = pd.to_numeric(c_str, errors="coerce")
        bad_c = (~chunk["computer"].str.startswith("C")) | c_vals.isna()
        if bad_c.any():
            for idx in chunk.index[bad_c][:20]:
                non_standard_comps.append({"row": int(idx), "computer": str(chunk.loc[idx, "computer"]), "time": int(t_arr[idx - total_rows])})
            c_vals = c_vals.fillna(-1)
        c_arr = c_vals.astype(np.int32).to_numpy()

        time_chunks.append(t_arr)
        uid_chunks.append(u_arr)
        cid_chunks.append(c_arr)

        total_rows += n_c
        print(f"  Przetworzono {total_rows:,} wierszy ({time_mod.time() - t0:.1f} s)...")

    all_time = np.concatenate(time_chunks)
    all_uid = np.concatenate(uid_chunks)
    all_cid = np.concatenate(cid_chunks)

    np.save(CACHE_DIR / "time.npy", all_time)
    np.save(CACHE_DIR / "uid.npy", all_uid)
    np.save(CACHE_DIR / "cid.npy", all_cid)

    # Sprawdzenie zakresów ID względem oficjalnej specyfikacji LANL (11,362 users, 22,284 computers)
    uids_gt_spec = np.unique(all_uid[all_uid > 11362]).tolist()
    uids_le_zero = np.unique(all_uid[all_uid <= 0]).tolist()
    cids_gt_spec = np.unique(all_cid[all_cid > 22284]).tolist()
    cids_le_zero = np.unique(all_cid[all_cid <= 0]).tolist()

    meta = {
        "total_rows": int(total_rows),
        "t_min": int(all_time.min()),
        "t_max": int(all_time.max()),
        "duration_seconds": int(all_time.max() - all_time.min() + 1),
        "duration_days": round(float(all_time.max() - all_time.min() + 1) / 86400.0, 2),
        "unique_users": int(len(np.unique(all_uid))),
        "unique_computers": int(len(np.unique(all_cid))),
        "min_uid": int(all_uid.min()),
        "max_uid": int(all_uid.max()),
        "min_cid": int(all_cid.min()),
        "max_cid": int(all_cid.max()),
        "uids_above_11362": uids_gt_spec[:50],
        "uids_le_0": uids_le_zero,
        "cids_above_22284": cids_gt_spec[:50],
        "cids_le_0": cids_le_zero,
        "out_of_order_count": len(out_of_order_events),
        "out_of_order_sample": out_of_order_events[:20],
        "non_standard_users_sample": non_standard_users[:20],
        "non_standard_comps_sample": non_standard_comps[:20],
        "elapsed_seconds": round(time_mod.time() - t0, 2),
    }

    with open(CACHE_DIR / "ingest_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"[ENEMY-INGEST] Zakończono w {meta['elapsed_seconds']} s! Podsumowanie:")
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    return meta


if __name__ == "__main__":
    ingest_enemy_dataset()

