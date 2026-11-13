# Proces Myślowy i Ścieżka Inżynieryjna (Reasoning) – Etap 1: Ukrywanie Naszych Ataków i Walidacja (Red Team)

Dokument opisuje krok po kroku tok rozumowania, przeprowadzone testy diagnostyczne, napotkane pułapki w prawdziwych danych LANL oraz decyzje projektowe podjęte podczas przygotowywania naszego zmodyfikowanego wycinka danych (`data/modified_for_enemy/auth_modified.csv`).

---

## Krok 1: Inspekcja uszkodzonego/przerwanego pliku `auth.txt` ($39.4\text{ GB}$)

### Problem wyjściowy
Pobieranie oryginalnego pliku `auth.txt.gz` zostało przerwane w połowie, ale plik udało się rozpakować do `data/raw/auth.txt/auth.txt` (rozmiar na dysku: $39\,405\,321\,533\text{ bajtów} \approx 36.7\text{ GiB}$) i otwierał się poprawnie w Notepad++.

### Co sprawdziliśmy w pierwszej kolejności?
1. Odczytaliśmy strumieniowo pierwsze 15 wierszy `data/raw/auth.txt/auth.txt` oraz pierwsze 10 wierszy `data/raw/redteam.txt`:
   * Pierwsze wiersze `auth.txt` zaczynały się poprawnie od sekundy `t = 1` i posiadały dokładnie 9 kolumn zgodnych ze specyfikacją LANL (`time,src_user,dst_user,src_computer,dst_computer,auth_type,logon_type,auth_orientation,status`).
   * W pliku `redteam.txt` sprawdziliśmy dokładny czas pierwszego prawdziwego ataku Red Teamu LANL:
     ```
     150885,U620@DOM1,C17693,C1003
     151036,U748@DOM1,C17693,C305
     151648,U748@DOM1,C17693,C728
     ```
   * **Wniosek:** Pierwszy atak w oryginalnym zbiorze LANL pojawia się dopiero w sekundzie **$t = 150\,885$** (pod koniec 2. doby). Ponieważ nasz wycinek pobieramy z początku zbioru (Doba 1, pierwsze kilkadziesiąt megabajtów z $39.4\text{ GB}$), przerwanie pobierania na dalszych gigabajtach pliku nie ma żadnego wpływu na spójność naszych danych, a wycinek dla $t_{\text{end}} < 150\,000$ jest w **100% wolny od oryginalnych ataków LANL**.

---

## Krok 2: Dobór okna czasowego – dlaczego zmieniliśmy `start_time` z $20\,000$ na $15\,000$?

### Pierwsza próba (`t_start = 20,000`, `target_rows = 450,000`)
* Uruchomiliśmy `src/slicer.py` dla początkowych parametrów `start_time = 20_000` i `target_rows = 450_000`.
* Skrypt wyciął $450\,125$ wierszy, które objęły przedział czasu $t \in [20\,000,\; 23\,710]$, czyli **zaledwie $\Delta T = 3\,711\text{ s}$ ($\approx 1.03\text{ godziny}$)**.

### Zidentyfikowany problem matematyczny
* Zgodnie ze specyfikacją projektu:
  1. W **Ataku 2 (C2 Beaconing)** bot wysyła zapytania co stały okres $T = 90\text{ s}$ z jitterem $\epsilon_k \in \{-2, -1, 0, 1, 2\}$.
  2. W module walidującym (`src/self_validator.py`) analiza IAT, współczynnika zmienności $CV$ i testu Kołmogorowa-Smirnowa filtruje pary `(src_user, dst_computer)` posiadające **co najmniej $50$ połączeń** ($\ge 50$).
* W oknie o długości $3\,711\text{ s}$ liczba cykli o okresie $T = 90\text{ s}$ wynosi:
  $$\left\lfloor \frac{3711}{90} \right\rfloor + 1 = 42 < 50$$
  Oznaczało to, że para odpowiedzialna za C2 Beaconing miałaby tylko 42 zdarzenia `LogOn` i zostałaby odrzucona przez filtr $\ge 50$ połączeń!

### Diagnostyka gęstości zdarzeń w `auth.txt`
Przeskanowaliśmy natężenie ruchu w `auth.txt` w blokach po $5\,000\text{ s}$ od $t = 0$ do $t = 80\,000$:
```
t=     0..  4999:  489,044 rows (97.8 rows/s)
t=  5000..  9999:  491,224 rows (98.2 rows/s)
t= 10000.. 14999:  488,059 rows (97.6 rows/s)
t= 15000.. 19999:  493,247 rows (98.6 rows/s)
t= 20000.. 24999:  674,993 rows (135.0 rows/s)
t= 25000.. 29999: 1,272,651 rows (254.5 rows/s)
```
* Zauważyliśmy, że w przedziale $t \in [15\,000,\; 20\,000]$ ruch jest spokojniejszy ($\approx 98.6\text{ wierszy/s}$), a dokładnie po $t = 20\,000$ zaczyna się poranny wzrost aktywności ($\approx 135\text{ wierszy/s}$).
* **Decyzja:** Ustawiliśmy `SLICE_START_TIME = 15_000` oraz `SLICE_TARGET_ROWS = 550_000` (nadal w wymaganym przedziale $300\text{k} \text{ -- } 600\text{k}$ rekordów).
* **Efekt:** Wycięty zbiór objął $550\,053$ wiersze w przedziale $t \in [15\,000,\; 20\,560]\text{ s}$, co dało **$\Delta T = 5\,561\text{ s}$ ($\approx 1.54\text{ h}$)**:
  * Uchwyciliśmy zmianę reżimu ruchu (przejście z godzin porannych w szczyt po $t = 20\,000$).
  * Liczba cykli C2 Beaconing ($T = 90\text{ s}$) wzrosła do **$62$ połączeń `LogOn`** ($62 \ge 50$), gwarantując przejście przez próg walidatora.

---

## Krok 3: Analiza tła (EDA) i wykrycie pułapek w danych LANL

Przed wstrzyknięciem ataków zbadaliśmy statystyki czystego wycinka (`550,053` wierszy), co ujawniło **4 krytyczne pułapki**, które bez wcześniejszej analizy mogłyby zdradzić nasze ataki lub zakłócić detekcję:

### Pułapka 1: Tło nieudanych logowań (`Fail`) a wykrywalność Password Spraying
* Sprawdziliśmy rozkład zdarzeń `Fail` w czystym wycinku:
  * W oknach 1-minutowych: $\text{mediana} = 37.0$, $\text{MAD} = 7.0$, wartość maksymalna tła $= 73$ (co daje maksymalny zmodyfikowany Z-score tła $M_t = 3.47 < 3.5$).
  * W oknach 5-minutowych: $\text{mediana} = 191.0$, $\text{MAD} = 13.0$, wartość maksymalna tła $= 242$ ($M_t = 2.65 < 3.5$).
  * Rozkład `Fail` po typach uwierzytelniania: `{'?': 2703, 'NTLM': 352, 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0': 258, 'Negotiate': 200, 'Kerberos': 23}`.
* **Wniosek projektowy:** Gdybyśmy rozciągnęli $180$ błędów `Fail` ($60 \text{ kont} \times 3 \text{ próby}$) równomiernie na pełne $10\text{ minut}$ ($+18\text{ błędów/min}$), to w oknie 1-minutowym suma wyniosłaby $37 + 18 = 55$, czyli mniej niż naturalne maksimum tła ($73$)!
* **Rozwiązanie:** W naszym generatorze `inject_password_spraying()` krok między kolejnymi testowanymi użytkownikami wynosi $\Delta t \sim \mathcal{N}(3, 1)\text{ s}$, a dla każdego użytkownika wykonywane są 3 szybkie próby haseł. Dzięki temu całe rozpylanie zamyka się w $\approx 181\text{ s}$ wewnątrz jednego okna 5-minutowego ($t \in [16\,800,\; 16\,981]$). W efekcie:
  * W oknach 1-minutowych liczba `Fail` skacze do $107\text{ / min}$ ($M_t = 5.90 > 3.5$).
  * W oknie 5-minutowym liczba `Fail` skacze do $379\text{ / 5 min}$ ($M_t = 7.04 > 3.5$).
  * Żadne inne okno w całym zbiorze nie przekracza progu $M_t = 3.5$ ($100\%$ precyzji, $0$ fałszywych alarmów).

### Pułapka 2: Naturalne skrypty okresowe co $30.00\text{ s}$ w tle LANL
* Podczas badania par `(src_user, dst_computer)` o liczbie połączeń $\ge 50$ w czystym wycinku zauważyliśmy, że w sieci LANL działają automatyczne zadania cykliczne (np. `U108@DOM1 -> C1691`, `U51@DOM1 -> C1487`), które logują się dokładnie co $30.00\text{ s}$ ($CV \approx 0.000 \text{ -- } 0.005$).
* **Rozwiązanie:** Nasz bot C2 (`U179@DOM1 -> C612`) używa protokołu `NTLM`, okresu $T = 90\text{ s}$ ($\mu_\tau = 90.0\text{ s} > 45\text{ s}$) oraz realistycznego jittera $\epsilon_k \in \{-2, -1, 0, 1, 2\}\text{ s}$ ($CV = 0.02091$). Ponadto wybraliśmy serwer docelowy `C612`, z którym konto `U179@DOM1` nie miało wcześniej połączeń w wycinku, dzięki czemu szereg czasowy IAT tej pary nie jest zanieczyszczony ruchem tła.

### Pułapka 3: Skaner administracyjny `U66@DOM1` oraz błędny wpis `"U22"` w kolumnie komputerów
* W czystym wycinku odkryliśmy konto `U66@DOM1`, które naturalnie łączy się z $97$ komputerami (skaner systemowy), podczas gdy każdy zwykły pracownik łączy się z najwyżej $10 \text{ -- } 14$ komputerami.
* Dodatkowo zauważyliśmy, że w oryginalnym pliku LANL w kilku wierszach w kolumnie `dst_computer` pojawia się wartość `"U22"` (zamiast `"C..."`).
* **Rozwiązanie:**
  1. W `src/eda_baseline.py` wymusiliśmy filtr `str.startswith("C")` dla puli komputerów klienckich i docelowych, eliminując `"U22"` z listy celów Lateral Movement.
  2. W `src/attack_injector.py` zaprojektowaliśmy **Lateral Movement (`U1711@DOM1`)** jako **wieloskokowy łańcuch przesiadek (`C5830 -> C1444 -> C1537 -> C5946`, 4 skoki)** połączony z rozgałęzieniem (*fan-out*) z hosta pośredniego `C5946` na $35$ unikalnych komputerów docelowych. Dzięki dodaniu do `src/self_validator.py` cechy grafowej `max_chain_hops` (długość najdłuższej ścieżki prostej w grafie skierowanym logowań użytkownika), konto `U1711@DOM1` osiąga `max_chain_hops = 4` (podczas gdy `U66@DOM1` loguje się płasko z jednego hosta) i zajmuje bezapelacyjnie 1. miejsce w rankingu anomalii.

### Pułapka 4: Weryfikacja reguły OPSEC `Fail` $\Rightarrow$ `Success`
* Przy pierwszym uruchomieniu `verify_opsec()` asercja zgłosiła $44$ użytkowników mających `Fail` bez `Success`.
* Okazało się, że w samym czystym wycinku 1.54-godzinnym LANL istnieje $44$ użytkowników, którzy zaliczyli błędne logowanie w tej godzinie, ale ich udane logowanie miało miejsce w innej godzinie 58-dniowego zbioru.
* Natomiast wszystkie $60$ kont wybranych przez nas jako ofiary Password Sprayingu pochodziło z puli `moderate_human_users` (posiadających $\ge 5$ udanych logowań `Success` wewnątrz naszego wycinka). Doprecyzowaliśmy test OPSEC tak, aby weryfikował obecność `Success` w wycinku dla wszystkich wstrzykniętych celów (`injected_fail_users_without_success == 0`).

---

## Krok 4: Powiązanie 3 ataków w spójny łańcuch Cyber Kill Chain

Zamiast wstrzykiwać 3 niezależne, oderwane od siebie anomalie, połączyliśmy je przyczynowo-skutkowo:
1. **Etap 1 (`t = 16,800 .. 16,981 s`):** Z przejętej stacji roboczej `C5989` agresor przeprowadza **Password Spraying** na kontroler domeny `C586` wobec $60$ kont pracowników. Dla $58$ kont wszystkie 3 próby kończą się statusem `Fail`, natomiast dla **2 kont (`U179@DOM1` oraz `U1711@DOM1`)** ostatnia próba kończy się statusem `Success` (odgadnięcie hasła).
2. **Etap 2 (`t = 15,016 .. 20,506 s`):** Pierwsze przejęte konto **`U179@DOM1`** (ze stacji `C574`) utrzymuje kanał **C2 Beaconing** do serwera `C612` (`NTLM`, `Network`, `LogOn`, okres $T = 90\text{ s}$, jitter $\pm 2\text{ s}$, łącznie $62$ cykle `LogOn` + $62$ `LogOff`).
3. **Etap 3 (`t = 17,200 .. 18,937 s`):** Chwilę po udanym Password Sprayingu drugie przejęte konto **`U1711@DOM1`** wykonuje **Lateral Movement**: najpierw przeskakuje kaskadowo przez łańcuch 4 maszyn `C5830 -> C1444 -> C1537 -> C5946`, a następnie z maszyny `C5946` przeprowadza rekonesans SMB/Network (`Negotiate`) na $35$ nowych komputerów w sieci.

---

## Krok 5: Dopracowanie skalowania PCA 2D i wizualizacji (`300 DPI`)

* Po pierwszym wygenerowaniu wykresu `fig3_ml_pca_clustering_lateral_movement.png` zauważyliśmy, że składowa `PC1` pochłaniała aż $99.7\%$ wariancji (rozciągając oś od $0$ do $1100$), ponieważ pojedyncza cecha `total_logons` miała silnie skośny rozkład (jedno konto systemowe z $6\,787$ logowaniami).
* Zastosowaliśmy transformację logarytmiczną `np.log1p()` dla silnie skośnych cech liczbowych (`total_logons`, `unique_dst_computers`, `unique_src_computers`, `mean_iat`) oraz połączenie `RobustScaler` ze standaryzacją wariancji przed rzutowaniem PCA.
* Po korekcie wariancja rozłożyła się harmonijnie (`PC1 = 36.2%`, `PC2 = 18.8%`), klaster normalnych użytkowników skupił się wokół `(0, 0)`, a konto `U1711@DOM1` zostało wyraźnie odseparowane w prawym górnym rogu wykresu bez nakładania się etykiet na legendę.

