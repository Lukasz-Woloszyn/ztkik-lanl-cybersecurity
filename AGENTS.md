# AGENTS.md - Specyfikacja Projektu ZTKIK (LANL Cyber-Security)

## 1. Kontekst Projektu i Bieżący Cel Agenta

Jesteś inżynierem Data Science, Cyberbezpieczeństwa oraz Kryptoanalizy Statystycznej wspierającym realizację projektu z przedmiotu **ZTKIK (Zaawansowane Techniki Kryptografii i Kryptoanalizy)**.

**BIEŻĄCY PRIORYTET (ETAP 1 – NASZA CZĘŚĆ / RED TEAM + WALIDACJA):**
Nasza grupa pracuje na zbiorze **LANL Dataset 1 (`cyber1`)**, konkretnie na tablicy uwierzytelnień **`auth.txt.gz`**. Nie przesyłamy całego wielogigabajtowego zbioru, lecz operujemy na wycinku rzędu **$300\,000 \text{ -- } 600\,000$ rekordów**.

Twoim zadaniem w Etapie 1 jest:
1. Wycięcie czystego, ciągłego czasowo wycinka danych z `auth.txt.gz` (strumieniowo, bez konieczności rozpakowywania całego pliku $12\text{ GB}$ do pamięci RAM).
2. Przeprowadzenie eksploracyjnej analizy danych (EDA) na wycinku bazowym, aby dobrać realistyczne konta użytkowników i komputerów.
3. Zaimplementowanie generatora i wstrzykiwacza 3 zaawansowanych ataków cybernetycznych z zachowaniem pełnego kamuflażu (OPSEC) i spójności formatu LANL.
4. Zbudowanie modułu **Self-Validator** (opartego na metodach statystycznych, szeregach czasowych, klastrowaniu i Isolation Forest), który udowodni matematycznie, że nasze ataki są wykrywalne i wygeneruje wykresy do raportu.

*(Uwaga: Etap 2, czyli analiza danych od grupy przeciwnej, zostanie zrealizowany w przyszłości, gdy druga grupa wybierze swój zbiór i przekaże nam plik).*

---

## 2. Stos Technologiczny

Ponieważ pracujemy na wycinku ok. $300\,000 \text{ -- } 600\,000$ rekordów, dane po wycięciu mieszczą się swobodnie w pamięci RAM, co pozwala na użycie pełnego ekosystemu naukowego Pythona:
* **Język:** Python 3.11+
* **Ekstrakcja strumieniowa i przetwarzanie:** wbudowany moduł `gzip`, `polars` lub `pandas`, `numpy`.
* **Statystyka i szeregi czasowe:** `scipy.stats` (testy Kołmogorowa-Smirnowa, entropia Shannona), `statsmodels` (ACF, STL), `numpy.fft` (analiza widmowa FFT).
* **Anomalie i Klastrowanie (ML):** `scikit-learn` (`IsolationForest`, `LocalOutlierFactor`, `DBSCAN`, `RobustScaler`, `PCA`).
* **Analiza grafowa:** `networkx`.
* **Wizualizacja:** `matplotlib`, `seaborn` (zapis wykresów w `300 DPI` do `reports/figures/`).

---

## 3. Schemat Tablicy `auth.txt.gz` (LANL Dataset 1)

Plik CSV bez wiersza nagłówkowego, wartości rozdzielane przecinkiem (`,`), brakujące wartości oznaczone jako `?`. Czas `time` to sekundy (liczba całkowita dodatnia).

**Kolejność i nazwy kolumn (9 kolumn):**
1. `time` (`int64`) – znacznik czasu w sekundach (np. `1`, `2`, ...).
2. `src_user` (`str`) – użytkownik źródłowy z domeną (np. `U147@DOM1`, `C625$@DOM1`, `ANONYMOUS LOGON@C586`).
3. `dst_user` (`str`) – użytkownik docelowy z domeną (np. `U147@DOM1`, `SYSTEM@C653`).
4. `src_computer` (`str`) – komputer źródłowy (np. `C625`).
5. `dst_computer` (`str`) – komputer docelowy (np. `C625`, `C586`).
6. `auth_type` (`str`) – typ uwierzytelniania (np. `Negotiate`, `Kerberos`, `NTLM`, `?`).
7. `logon_type` (`str`) – typ logowania (np. `Batch`, `Service`, `Network`, `Interactive`, `Unlock`, `?`).
8. `auth_orientation` (`str`) – orientacja zdarzenia (np. `LogOn`, `LogOff`, `TGS`, `TGT`, `AuthMap`).
9. `status` (`str`) – wynik uwierzytelniania (`Success` lub `Fail`).

*Przykładowe oryginalne wiersze:*
```
1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success
1,C653$@DOM1,SYSTEM@C653,C653,C653,Negotiate,Service,LogOn,Success
```

---

## 4. Architektura Katalogów i Plików

Utrzymuj następującą strukturę projektu:

```
.
├── AGENTS.md
├── PLAN_PROJEKTU_ZTKIK.md
├── requirements.txt
├── data/
│   ├── raw_lanl/             # Miejsce na oryginalny plik auth.txt.gz (lub wygenerowany syntetyczny odpowiednik do testów)
│   ├── raw_slice/            # Wycięty czysty podzbiór (np. 400k-500k wierszy) bez naszych ataków
│   ├── modified_for_enemy/   # Podzbiór po wstrzyknięciu ataków (plik do oddania drugiej grupie)
│   ├── secret_ground_truth/  # Tajny manifest JSON z dokładnymi szczegółami wstrzykniętych ataków
│   └── received_from_enemy/  # (Placeholder na Etap 2 - dane od grupy przeciwnej)
├── src/
│   ├── config.py             # Parametry wycinka (liczba wierszy, okno czasu) i parametry ataków
│   ├── slicer.py             # Strumieniowe wycinanie ciągłego okna czasowego z auth.txt.gz
│   ├── eda_baseline.py       # Analiza czystego wycinka i wybór odpowiednich kont/komputerów do symulacji
│   ├── attack_injector.py    # Generator 3 scenariuszy ataków + scalanie + sortowanie + weryfikacja OPSEC
│   └── self_validator.py     # Potok analityczny (Statystyka, Szeregi Czasowe, ML, Grafy) weryfikujący wykrywalność naszych ataków
└── reports/
    ├── figures/              # Wykresy (300 DPI) potwierdzające działanie symulacji i detekcji
    └── red_team_summary.md   # Automatyczny raport opisujący wstrzyknięte ataki i dowody matematyczne ich wykrywalności
```

---

## 5. Szczegółowe Wytyczne Implementacyjne dla Modułów

### Moduł 1: `src/slicer.py` (Ekstrakcja wycinka)
* Otwórz plik `auth.txt.gz` strumieniowo (`gzip.open(..., 'rt')`), aby zużycie pamięci RAM było bliskie zeru.
* Pomiń początkowy rozruch (np. zacznij od wybranego `start_time`, np. $t = 20\,000$) i pobierz ciągły blok zdarzeń o zadanej wielkości docelowej (domyślnie `target_rows = 450_000`), upewniając się, że pobierasz wszystkie zdarzenia aż do końca ostatniej sekundy $t_{\text{end}}$ (aby nie uciąć sekundy w połowie).
* **WAŻNE:** Upewnij się, że $t_{\text{end}} < 151\,648$ (przed pierwszym zdarzeniem z oryginalnego `redteam.txt.gz`), dzięki czemu wycinek jest w 100% wolny od oryginalnych ataków LANL.
* *Tryb testowy (Fallback):* Jeśli użytkownik nie pobrał jeszcze dużego pliku `auth.txt.gz`, udostępnij funkcję `generate_synthetic_lanl_slice(n_rows=400_000)`, która generuje realistyczny wycinek zgodny ze schematem LANL (rozkład Poissona z cyklem dobowym, konta `U...@DOM1` i `C...$@DOM1`), aby cały potok można było przetestować natychmiast.

### Moduł 2: `src/eda_baseline.py` (Analiza tła i dobór aktorów)
* Wczytaj `data/raw_slice/auth_clean_slice.csv`.
* Zidentyfikuj:
  1. Listę aktywnych użytkowników ludzkich (zaczynających się od `U`, np. `U123@DOM1`), którzy mają co najmniej jedno zdarzenie `Success` w wycinku (wymóg dokumentacji LANL dla zdarzeń `Fail`).
  2. Listę aktywnych komputerów klienckich oraz serwerów (komputery o wysokim stopniu wejściowym `in_degree`, np. kontrolery domeny lub serwery plików).
  3. Rozkład liczby zdarzeń w czasie (w oknach 1-minutowych i 5-minutowych).

### Moduł 3: `src/attack_injector.py` (Generator i Wstrzykiwacz Ataków)
Zaimplementuj 3 modularne funkcje generujące ataki na podstawie rzeczywistych encji z wycinka:

1. **`inject_password_spraying()`**:
   * Wybiera 1 komputer źródłowy `C_src`, 1 serwer docelowy `C_srv` oraz $N = 60$ istniejących użytkowników `U_i@DOM1`.
   * W oknie $\Delta T = 600\text{ s}$ generuje po $3$ nieudane próby (`Kerberos`, `Network`, `LogOn`, `Fail`) dla każdego z $60$ użytkowników w odstępach z rozkładu normalnego $\Delta t \sim \mathcal{N}(3, 1)$, a dla $2$ wybranych użytkowników kończy logowaniem udanym (`Success`).

2. **`inject_c2_beaconing()`**:
   * Wybiera 1 przejętego użytkownika `U_bot@DOM1`, jego komputer `C_bot` oraz docelowy serwer `C_c2`.
   * Przez cały czas trwania wycinka (lub wybrane $4\text{ godziny}$) wstawia cykliczne uwierzytelnienia sieciowe (`NTLM`, `Network`, `LogOn`, `Success`) w chwilach:
     $$t_k = t_{\text{start}} + k \cdot T + \epsilon_k, \quad T = 90\text{ s}, \quad \epsilon_k \in \{-2, -1, 0, 1, 2\}$$

3. **`inject_lateral_movement()`**:
   * Wybiera 1 przejętego użytkownika `U_lat@DOM1`.
   * W oknie $1800\text{ s}$ ($30\text{ minut}$) tworzy kaskadę logowań: najpierw łańcuch `C_1` $\rightarrow$ `C_2` $\rightarrow$ `C_3` $\rightarrow$ `C_4`, a następnie z `C_4` serię logowań (`Negotiate`, `Network`, `LogOn`, `Success`) na $35$ różnych komputerów docelowych, na które to konto nigdy wcześniej się nie logowało.

**Reguły zapisu (`inject_pipeline`):**
* Połącz oryginalny wycinek z wygenerowanymi wierszami.
* Posortuj stabilnie po kolumnie `time` rosnąco (`kind='mergesort'`).
* Zapisz zmodyfikowany plik bez nagłówka do `data/modified_for_enemy/auth_modified.csv`.
* Zapisz pełną dokumentację wstrzyknięć do `data/secret_ground_truth/manifest.json` (dokładne czasy, użyte konta, liczba wstrzykniętych rekordów).

### Moduł 4: `src/self_validator.py` (Weryfikacja Statystyczna i ML)
Ten moduł ładuje `data/modified_for_enemy/auth_modified.csv` (udając, że nie zna `manifest.json`) i przeprowadza pełną analizę wymaganą na przedmiocie ZTKIK, a na końcu porównuje wyniki z `manifest.json`:

1. **Analiza szeregu czasowego:**
   * Agregacja w oknach 1-minutowych i 5-minutowych (ogólna liczba logowań oraz liczba zdarzeń `Fail`).
   * Obliczenie modyfikowanego wskaźnika Z-score opartego na medianie i MAD:
     $$M_t = \frac{0.6745 \cdot |Y_t - \text{median}(Y)|}{\text{MAD}}$$
   * Wykres szeregu czasowego z zaznaczonym pikiem podczas *Password Spraying*.

2. **Analiza statystyczna i widmowa (IAT + FFT/ACF):**
   * Dla par `(src_user, dst_computer)` o liczbie połączeń $\ge 50$ oblicza odstępy czasu między zdarzeniami $\tau_i = t_i - t_{i-1}$, współczynnik zmienności $CV = \frac{\sigma_{\tau}}{\mu_{\tau}}$ oraz wykonuje test Kołmogorowa-Smirnowa przeciwko rozkładowi wykładniczemu.
   * Wykrywa parę odpowiedzialną za *C2 Beaconing* i rysuje dla niej wykres rozkładu IAT oraz periodogram FFT / autokorelację ACF z wyraźnym pikiem dla $T = 90\text{ s}$.

3. **Analiza Entropii, Klastrowanie i Isolation Forest:**
   * Buduje profil każdego użytkownika: liczba logowań, liczba unikalnych komputerów docelowych, entropia Shannona komputerów docelowych $H(C \mid U = u)$, odsetek nieudanych logowań, średnie IAT.
   * Uruchamia **Isolation Forest**, **LOF** oraz **DBSCAN** i rysuje rzutowanie **PCA 2D** z wyraźnie oznaczonymi anomaliami (w tym kontem wykonującym *Lateral Movement* oraz komputerem wykonującym *Password Spraying*).

4. **Generowanie Raportu (`reports/red_team_summary.md`):**
   * Zapisuje gotowe podsumowanie z tabelami wyników, wartościami $p\text{-value}$, entropią i Z-score, które studenci mogą bezpośrednio wykorzystać w sprawozdaniu projektowym.

---

## 6. Kolejność Działań Agenta przy Starce

Gdy użytkownik poprosi o rozpoczęcie implementacji:
1. Utwórz katalogi projektu oraz `requirements.txt`.
2. Zaimplementuj `src/config.py` oraz `src/slicer.py` (z obsługą prawdziwego pliku `auth.txt.gz` oraz generatorem realistycznej próbki testowej, jeśli plik `auth.txt.gz` nie jest jeszcze obecny w `data/raw_lanl/`).
3. Zaimplementuj `src/eda_baseline.py`, `src/attack_injector.py` oraz `src/self_validator.py`.
4. Uruchom cały potok end-to-end, zweryfikuj czy wszystkie 3 ataki są wykrywane z wysoką precyzją i wygeneruj wykresy w `reports/figures/` oraz raport w `reports/red_team_summary.md`.