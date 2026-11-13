# Projekt ZTKIK – Zaawansowane Techniki Kryptografii i Kryptoanalizy (LANL Cyber-Security)

Kompleksowe rozwiązanie projektowe realizowane w formule **Red Team vs. Blue Team** na rzeczywistych zbiorach logów uwierzytelnień **Los Alamos National Laboratory (LANL)**:

1. **Etap 1 (Red Team + Self-Validator – nasza strona):** Strumieniowa ekstrakcja czystego wycinka z 9-kolumnowego zbioru **LANL Dataset 1 (`auth.txt` / $39.4\text{ GB}$)**, eksploracyjna analiza tła (EDA), wstrzyknięcie 3 powiązanych w łańcuch *Cyber Kill Chain* ataków cybernetycznych z zachowaniem pełnego kamuflażu OPSEC oraz matematyczny dowód ich wykrywalności.
2. **Etap 2 (Blue Team / Kryptoanaliza Danych Przeciwnika):** Kryminalistyczna, statystyczna, widmowa (FFT/ACF) oraz oparta na uczeniu maszynowym (`Isolation Forest`, `LOF`, `DBSCAN`, `PCA 2D`, `NetworkX`) detekcja 4 scenariuszy ataków ($117$ rekordów, $19$ kont) ukrytych przez grupę przeciwną w 3-kolumnowym zbiorze **LANL *"User-Computer Authentication Associations in Time"* ($1.60\text{ GB}$, $75\,868\,965$ wierszy)**.

---

## Spis Dokumentacji, Raportów i Reasoningów

* **Raporty główne (gotowe do sprawozdania):**
  * [reports/red_team_summary.md](reports/red_team_summary.md) – Raport Etapu 1: opis naszych 3 wstrzykniętych ataków i dowody matematyczne ich wykrywalności.
  * [reports/blue_team_enemy_analysis.md](reports/blue_team_enemy_analysis.md) – Raport Etapu 2: pełna rekonstrukcja i dowody detekcji 4 scenariuszy ataków w zbiorze grupy przeciwnej.
* **Dokumenty Reasoning (szczegółowy opis krok po kroku jak myśleliśmy, co sprawdzaliśmy i jak dochodziliśmy do wyników):**
  * [reports/REASONING_RED_TEAM_NASZE_ATAKI.md](reports/REASONING_RED_TEAM_NASZE_ATAKI.md) – Tok rozumowania przy projektowaniu, ukrywaniu i walidacji naszych ataków (Etap 1).
  * [reports/REASONING_BLUE_TEAM_ATAKI_PRZECIWNIKA.md](reports/REASONING_BLUE_TEAM_ATAKI_PRZECIWNIKA.md) – Ścieżka śledcza krok po kroku przy odkrywaniu ataków grupy przeciwnej w pliku $75.87\text{ mln}$ wierszy (Etap 2).
* **Manifesty i wyekstrahowane anomalie:**
  * [data/secret_ground_truth/manifest.json](data/secret_ground_truth/manifest.json) – Ground Truth naszych wstrzykniętych ataków (Etap 1).
  * [data/received_from_enemy/detected_enemy_attacks.csv](data/received_from_enemy/detected_enemy_attacks.csv) – Wszystkie $117$ wykrytych wierszy ataków grupy przeciwnej z dokładnymi indeksami linii i czasami (Etap 2).
  * [data/received_from_enemy/detected_enemy_manifest.json](data/received_from_enemy/detected_enemy_manifest.json) – Pełny manifest statystyczny wykrytych ataków przeciwnika (Etap 2).

---

## Architektura Projektu

```text
.
├── AGENTS.md                                      # Specyfikacja techniczna projektu
├── PLAN_PROJEKTU_ZTKIK.md                         # Plan koncepcyjny Etapu 1
├── README.md                                      # Instrukcja uruchomienia i opis repozytorium
├── requirements.txt                               # Zależności Python
├── data/
│   ├── raw/ lub raw_lanl/                         # Surowy plik auth.txt / auth.txt.gz (ignorowany przez Git)
│   ├── raw_slice/
│   │   ├── auth_clean_slice.csv                   # Wycięty czysty wycinek 550,053 wierszy (t = 15000..20560)
│   │   └── eda_baseline_summary.json              # Statystyki tła i pule aktorów
│   ├── modified_for_enemy/
│   │   └── auth_modified.csv                      # Plik wynikowy z wstrzykniętymi atakami (550,659 wierszy)
│   ├── secret_ground_truth/
│   │   └── manifest.json                          # Tajny manifest Ground Truth naszych ataków
│   └── received_from_enemy/
│       ├── lanl-auth-dataset-advanced-attacked    # Plik 1.6 GB otrzymany od grupy przeciwnej (75.87 mln wierszy)
│       ├── detected_enemy_attacks.csv             # Wyekstrahowane 117 wierszy ataków grupy przeciwnej
│       └── detected_enemy_manifest.json           # Podsumowanie JSON wykrytych ataków przeciwnika
├── src/
│   ├── config.py                                  # Centralna konfiguracja ścieżek i hiperparametrów
│   ├── slicer.py                                  # Strumieniowe wycinanie okna czasowego (z trybem Fallback)
│   ├── eda_baseline.py                            # Eksploracyjna analiza czystego wycinka (EDA)
│   ├── attack_injector.py                         # Generator i wstrzykiwacz 3 ataków + kontrola OPSEC
│   ├── self_validator.py                          # Walidator statystyczny, widmowy i ML naszych ataków
│   ├── enemy_ingest.py                            # Szybki parser 1.6 GB CSV -> binarne tablice NumPy (.npy)
│   └── enemy_analyzer.py                          # Detektor kryminalistyczny, statystyczny i ML dla danych wroga
└── reports/
    ├── red_team_summary.md                        # Raport z części Red Team + Self-Validation
    ├── blue_team_enemy_analysis.md                # Raport z części Blue Team (analiza pliku przeciwnika)
    ├── REASONING_RED_TEAM_NASZE_ATAKI.md          # Opis rozumowania (Etap 1 - nasze ataki)
    ├── REASONING_BLUE_TEAM_ATAKI_PRZECIWNIKA.md   # Opis rozumowania (Etap 2 - ataki przeciwnika)
    └── figures/                                   # Wykresy w rozdzielczości 300 DPI (Etap 1 oraz Etap 2)
```

---

## Jak uruchomić i przetestować projekt samodzielnie?

### 1. Wymagania i instalacja zależności

Projekt wymaga **Pythona 3.10+**. Zainstaluj wymagane pakiety naukowe:

```bash
pip install -r requirements.txt
```

---

### 2. Uruchomienie Etapu 1 (Nasza strona: Wycięcie danych $\rightarrow$ EDA $\rightarrow$ Wstrzyknięcie ataków $\rightarrow$ Walidacja)

> **Uwaga dotycząca dużego pliku `auth.txt`:**  
> Jeśli w katalogu `data/raw/auth.txt/auth.txt` lub `data/raw_lanl/auth.txt.gz` znajduje się oryginalny zbiór LANL, `src/slicer.py` odczyta go strumieniowo w kilka sekund bez obciążania pamięci RAM.  
> **Tryb testowy (Fallback):** Jeśli sklonowałeś repozytorium z GitHuba i nie posiadasz na dysku $39\text{ GB}$ pliku `auth.txt`, `src/slicer.py` automatycznie wygeneruje realistyczny wycinek syntetyczny zgodny ze schematem LANL, dzięki czemu cały potok możesz przetestować od ręki!

Uruchom kolejne moduły z głównego katalogu projektu:

```bash
# Krok 1: Strumieniowe wycięcie czystego okna (domyślnie t = 15000..20560, ok. 550 tys. wierszy)
python -m src.slicer

# Krok 2: Eksploracyjna analiza tła (EDA) i dobór realistycznych kont/komputerów
python -m src.eda_baseline

# Krok 3: Wstrzyknięcie 3 ataków (Password Spraying, C2 Beaconing, Lateral Movement) + weryfikacja OPSEC
python -m src.attack_injector

# Krok 4: Uruchomienie walidatora (Z-score/MAD, KS-test, FFT/ACF, Entropia, IForest/LOF/DBSCAN) i generowanie wykresów
python -m src.self_validator
```

Po wykonaniu powyższych komend:
* Zmodyfikowany plik dla grupy przeciwnej znajdziesz w: `data/modified_for_enemy/auth_modified.csv`
* Manifest Ground Truth znajdziesz w: `data/secret_ground_truth/manifest.json`
* Wykresy (`300 DPI`) oraz raport znajdziesz w: `reports/figures/fig1..fig3_*.png` oraz `reports/red_team_summary.md`

---

### 3. Uruchomienie Etapu 2 (Analiza zbioru otrzymanego od grupy przeciwnej – Blue Team)

Upewnij się, że plik otrzymany od grupy przeciwnej znajduje się w lokalizacji:
`data/received_from_enemy/lanl-auth-dataset-advanced-attacked`

Następnie uruchom dwuetapowy potok analityczny:

```bash
# Krok 1: Jednorazowa konwersja pliku 1.6 GB (75.87 mln wierszy) do szybkiego cache'u binarnego NumPy (.npy)
# oraz wstępna kontrola kryminalistyczna OPSEC (czas wykonania: ok. 4 minuty)
python -m src.enemy_ingest

# Krok 2: Pełna ekstrakcja 117 wstrzykniętych rekordów, testy Kołmogorowa-Smirnowa, analiza ACF/FFT,
# klasteryzacja ML (Isolation Forest, LOF, DBSCAN, PCA 2D), analiza grafowa i generowanie raportu (czas: ok. 40 s)
python -m src.enemy_analyzer
```

Po wykonaniu powyższych komend:
* Lista wszystkich $117$ wykrytych wierszy ataków zostanie zapisana w: `data/received_from_enemy/detected_enemy_attacks.csv`
* Szczegółowy manifest JSON zostanie zapisany w: `data/received_from_enemy/detected_enemy_manifest.json`
* Wykresy (`300 DPI`) oraz raport końcowy znajdziesz w: `reports/figures/enemy_fig1..fig3_*.png` oraz `reports/blue_team_enemy_analysis.md`

---

## Podsumowanie Wyników

### Etap 1 – Nasze wstrzyknięte ataki (`auth_modified.csv`)
| Scenariusz | Aktorzy | Główne dowody wykrywalności (`self_validator.py`) |
| :--- | :--- | :--- |
| **1. Password Spraying** | `C5989` $\rightarrow$ `C586` ($N=60$ kont, przejęte: `U179@DOM1`, `U1711@DOM1`) | Zmodyfikowany Z-score: $M_t(5\text{m}) = 7.04 > 3.5$, $M_t(1\text{m}) = 5.90 > 3.5$, entropia celów $H(U \mid C_{\text{src}}) = 5.9293\text{ b}$ |
| **2. C2 Beaconing** | `U179@DOM1` (`C574` $\rightarrow$ `C612`, $T = 90\text{ s} \pm 2\text{ s}$, $62$ cykle) | $CV = 0.02091 \ll 1$, test KS: $D_{\text{KS}} = 0.6154, p = 9.28 \times 10^{-23}$, FFT: $T = 89.69\text{ s}$, $\text{ACF}(90\text{s}) = 0.6832$ |
| **3. Lateral Movement** | `U1711@DOM1` (łańcuch `C5830->C1444->C1537->C5946` + fan-out na $35$ hostów) | Długość łańcucha $= 4$ skoki, entropia $H(C_{\text{dst}} \mid U) = 5.3661\text{ b}$, `IForest = 0.7630`, `LOF = 2.5830`, `DBSCAN = -1` |

### Etap 2 – Wykryte ataki grupy przeciwnej (`lanl-auth-dataset-advanced-attacked`)
| Scenariusz | Wyzwalacz linii (`orig_line`) | Wykryte Konta | Główne dowody wykrywalności (`enemy_analyzer.py`) |
| :--- | :--- | :--- | :--- |
| **Scenariusz 1: Szybki Fan-out 5x5** | `range(5000, 80000, 15000)` (`25` wierszy) | `U8693, U3120, U3254, U257, U9517` | Synchroniczne logowania w $t = 12096001..12096009$ co $\Delta t = 2\text{ s}$ ($CV = 0.0$), $100\%$ singleton edges, `DBSCAN = -1` |
| **Scenariusz 2: Synchroniczny Burst 4x3** | `range(80000, 160000, 20000)` (`12` wierszy) | `U7321, U1789, U396, U1062` | Identyczne chwile $t \in \{12096101, 12096109, 12096116\}$ ($\Delta t = 8\text{ s}, 7\text{ s}$, $CV = 0.0667$), $100\%$ singleton edges |
| **Scenariusz 3: Beaconing Godzinowy 5x1** | `range(160000, 235000, 15000)` (`5` wierszy) | `U711, U337, U4077, U2851, U1456` | $t_k = 13096000 + k \cdot 3600$ (idealny krok $\Delta t = 3600\text{ s} = 1\text{ h}$, $CV = 0.0$), skok czasu $\Delta t \approx +10^6\text{ s}$ względem tła |
| **Scenariusz 4: Dobowy Botnet C2 5x15** | `range(250000, 300000, 10000)` (`75` wierszy) | `U24, U2867, U7230, U9578, U972` | $15$ dób co $T = 86\,400\text{ s}$ ($24\text{ h}$, $CV = 0.0$), przesunięcie fazowe między 5 botami $\Delta \phi = 300\text{ s}$ ($5\text{ min}$), test KS: $p = 1.23 \times 10^{-27}$, $\text{ACF}(24\text{h}) = 0.9332$ |

