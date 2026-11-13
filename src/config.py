"""
Konfiguracja projektu ZTKIK - Etap 1 (LANL Cyber1 Red Team + Self-Validator).
"""
from pathlib import Path

# Ścieżki katalogów głównych
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_LANL_DIR = DATA_DIR / "raw_lanl"
RAW_ALT_DIR = DATA_DIR / "raw"
RAW_SLICE_DIR = DATA_DIR / "raw_slice"
MODIFIED_DIR = DATA_DIR / "modified_for_enemy"
SECRET_GT_DIR = DATA_DIR / "secret_ground_truth"
RECEIVED_DIR = DATA_DIR / "received_from_enemy"

REPORTS_DIR = BASE_DIR / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

# Możliwe lokalizacje surowego pliku auth (obsługuje zarówno rozpakowany auth.txt jak i auth.txt.gz)
RAW_AUTH_CANDIDATES = [
    RAW_ALT_DIR / "auth.txt" / "auth.txt",
    RAW_ALT_DIR / "auth.txt",
    RAW_ALT_DIR / "auth.txt.gz",
    RAW_LANL_DIR / "auth.txt.gz",
    RAW_LANL_DIR / "auth.txt",
]

# Ścieżki plików wyjściowych Etapu 1
CLEAN_SLICE_PATH = RAW_SLICE_DIR / "auth_clean_slice.csv"
EDA_SUMMARY_PATH = RAW_SLICE_DIR / "eda_baseline_summary.json"
MODIFIED_AUTH_PATH = MODIFIED_DIR / "auth_modified.csv"
MANIFEST_PATH = SECRET_GT_DIR / "manifest.json"
REPORT_MD_PATH = REPORTS_DIR / "red_team_summary.md"

# Nazwy kolumn zgodne ze specyfikacją LANL auth.txt
AUTH_COLUMNS = [
    "time",
    "src_user",
    "dst_user",
    "src_computer",
    "dst_computer",
    "auth_type",
    "logon_type",
    "auth_orientation",
    "status",
]

# Parametry wycinania (Slicer)
# Pierwszy atak w oryginalnym redteam.txt występuje w t = 150885 (oraz 151648).
# Wybieramy ciągłe okno z Doby 1 począwszy od t = 15000 (przejście z godzin porannych w szczyt przy t=20000),
# co gwarantuje 100% czystości od oryginalnych ataków Red Teamu LANL, zmianę natężenia ruchu
# oraz czas trwania ~5500 s (>60 cykli C2 Beaconing o okresie T=90s dla progu >=50 połączeń).
SLICE_START_TIME = 15_000
SLICE_TARGET_ROWS = 550_000
MAX_SAFE_END_TIME = 150_000  # Musi być < 150885 (pierwszy wpis w redteam.txt)

# Ziarno generatora losowego dla pełnej powtarzalności (Reproducibility)
RANDOM_SEED = 42

# Parametry 3 wstrzykiwanych ataków (Attack Injector)
ATTACK_CONFIG = {
    "password_spraying": {
        "n_target_users": 60,
        "fails_per_user": 3,
        "n_compromised": 2,
        "window_seconds": 600,
        "iat_mean": 3.0,
        "iat_std": 1.0,
        "auth_type": "Kerberos",
        "logon_type": "Network",
        "auth_orientation": "LogOn",
    },
    "c2_beaconing": {
        "period_seconds": 90,
        "jitter_choices": [-2, -1, 0, 1, 2],
        "auth_type": "NTLM",
        "logon_type": "Network",
        "auth_orientation": "LogOn",
        "include_logoff": True,
        "logoff_delay_range": (1, 2),
    },
    "lateral_movement": {
        "window_seconds": 1800,
        "chain_length": 4,       # C_1 -> C_2 -> C_3 -> C_4
        "n_fanout_targets": 35,  # z C_4 na 35 unikalnych komputerów docelowych
        "attempts_per_target": 4, # wielokrotne sesje SMB/Network (LogOn + LogOff) na każdy cel
        "auth_type": "Negotiate",
        "logon_type": "Network",
        "auth_orientation": "LogOn",
    },
}
