# Plan Pracy nad Projektem ZTKIK – Etap 1: Przygotowanie Danych i Symulacja Ataków (Dane 1 – LANL `cyber1`)

## 1. Założenia dla Etapu 1 (Nasza część – Red Team)

Skupiamy się wyłącznie na przygotowaniu naszego wycinka danych ze zbioru **LANL Dataset 1 (`cyber1`)** oraz zasymulowaniu w nim ataków:
* **Rozmiar danych roboczych:** Zamiast operować na całym zbiorze ($12\text{ GB}$), wycinamy spójny czasowo wycinek rzędu **$300\,000 \text{ -- } 600\,000$ rekordów**. Taki rozmiar gwarantuje błyskawiczną pracę w pamięci RAM (w `pandas` / `polars`), łatwe przesłanie pliku drugiej grupie, a jednocześnie wystarczające „tło statystyczne”, by ukryć w nim zaawansowane ataki.
* **Wybór tablicy do modyfikacji:** Zgodnie z wymaganiami (*„symuluje poprzez modyfikację wybranej tablicy z danymi”*), najlepszym wyborem jest tablica **`auth.txt.gz`** (zdarzenia uwierzytelniania) lub alternatywnie **`flows.txt.gz`** (przepływy sieciowe). 
  * **Rekomendacja:** Wybierzmy **`auth.txt.gz`** jako tablicę główną. Posiada 9 bogatych informacyjnie kolumn, co pozwala zasymulować bardzo zróżnicowane ataki (zarówno czasowe, wolumetryczne, jak i grafowe).
* **Etap 2 (Analiza danych od drugiej grupy):** Zostaje odłożony do momentu, aż druga para wybierze swój zbiór i przekaże nam zmodyfikowany plik. Jednak już teraz zbudujemy **Lokalny Walidator (Self-Validator)**, którym przetestujemy nasze własne ataki – ten sam kod posłuży nam później jako baza do analizy danych przeciwników.

---

## 2. Jak mądrze wyciąć próbkę kilkuset tysięcy rekordów z `auth.txt.gz`?

Plik `auth.txt.gz` jest posortowany chronologicznie od sekundy $t = 1$. Aby nie rozpakowywać całego archiwum na dysk, napiszemy skrypt strumieniujący (`gzip.open`), który odczyta plik linijka po linijce i zapisze wybrany przedział czasu.

### Trzy złote zasady wyboru wycinka:
1. **Uniknięcie oryginalnych ataków LANL (`redteam.txt.gz`):** W oryginalnym zbiorze LANL prawdziwe ataki Red Teamu zaczynają się dopiero w sekundzie **$t = 151\,648$** (czyli pod koniec 2. doby). 
   * Jeśli wytniemy okno czasowe z **Doby 1 lub początku Doby 2** (np. między $t = 20\,000$ a $t = 120\,000$), mamy **100% pewności**, że w danych nie ma żadnych „obcych” ataków i jedyne anomalie w pliku to te, które sami wstrzykniemy!
2. **Spójne okno czasowe zamiast losowego próbkowania:** Nie losujemy pojedynczych wierszy z całego miesiąca, bo zniszczyłoby to szeregi czasowe. Wycinamy **ciągły przedział czasu** (np. kolejne $6 \text{ -- } 12\text{ godzin}$ ciągłej pracy sieci), który obejmuje np. $400\,000 \text{ -- } 500\,000$ kolejnych zdarzeń.
3. **Zachowanie cyklu aktywności:** Warto wybrać okno, które zahacza o zmianę natężenia ruchu (np. przejście z godzin nocnych/porannych w szczyt dzienny), co zmusi drugą grupę do uwzględnienia niestacjonarności szeregu czasowego.

---

## 3. Projekt 3 Ataków do Wstrzyknięcia w `auth.txt`

W wycinku liczącym ok. $500\,000$ wierszy chcemy wstrzyknąć łącznie ok. **$1\,000 \text{ -- } 2\,500$ spreparowanych zdarzeń** ($\approx 0.2\% \text{ -- } 0.5\%$ całego zbioru). Dzięki temu prosta inspekcja wzrokowa nic nie da, ale metody wymagane na ZTKIK (statystyka, szeregi czasowe, klastry, anomalie) wykryją je jednoznacznie.

### Atak 1: Password Spraying (Rozpylanie haseł) – *Cel: Analiza statystyczna, rozkłady i klasyfikacja wzorców*
* **Koncepcja:** Z jednego przejętego komputera wewnątrz sieci (`C_attacker`) skrypt próbuje zalogować się na wiele kont użytkowników (`U_target_1` ... `U_target_60`) jednym hasłem (np. `Wiosna2026!`), wykonując po $2 \text{ -- } 3$ próby na każde konto, aby nie zablokować kont w Active Directory.
* **Reprezentacja w `auth.txt`:**
  * Czas: zwarte okno np. $\Delta T = 600\text{ s}$ ($10\text{ minut}$).
  * Odstępy między próbami: $\Delta t \sim \mathcal{N}(\mu = 3\text{ s}, \sigma^2 = 1\text{ s}^2)$ zaokrąglone do pełnych sekund.
  * Kolumny: `time, U_target_i@DOM1, U_target_i@DOM1, C_attacker, C_DC_Server, Kerberos, Network, LogOn, Fail`.
  * Na końcu serii dla $2$ kont wstawiamy status `Success` (atakujący odgadł hasło dwóch pracowników!).
* **Jaki ślad zostawia (nasze uzasadnienie do raportu):**
  * Gwałtowny skok współczynnika `Fail / Success` w oknie 10-minutowym (anomalia w szeregu czasowym).
  * Wysoka **Entropia Shannona** użytkowników docelowych dla komputera `C_attacker`:
    $$H(U \mid C = c_{\text{attacker}}) = -\sum_{u} P(u \mid c_{\text{attacker}}) \log_2 P(u \mid c_{\text{attacker}})$$

### Atak 2: C2 Beaconing / Ukryty Bot Uwierzytelniający – *Cel: Szeregi czasowe (FFT, ACF) i testy rozkładu odstępów czasu (IAT)*
* **Koncepcja:** Jedno z przejętych w Ataku 1 kont (`U_compromised_1`) zostaje użyte przez złośliwy skrypt (implant), który przez cały okres naszego wycinka danych cyklicznie odpytuje wybrany serwer zasobów co stały okres $T = 90\text{ s}$ z niewielkim szumem losowym (*jitter*).
* **Reprezentacja w `auth.txt`:**
  * Czas: seria $300 \text{ -- } 400$ zdarzeń w chwilach:
    $$t_k = t_0 + k \cdot 90 + \epsilon_k, \quad \epsilon_k \in \{-2, -1, 0, 1, 2\}$$
  * Kolumny: `time, U_compromised_1@DOM1, U_compromised_1@DOM1, C_infected, C_FileServer, NTLM, Network, LogOn, Success` (oraz odpowiadające im zdarzenia `LogOff` po $1 \text{ -- } 2\text{ s}$).
* **Jaki ślad zostawia (nasze uzasadnienie do raportu):**
  * Ponieważ są to pojedyncze zdarzenia co $1.5\text{ minuty}$ ze statusem `Success`, w ogóle nie widać ich na zwykłym wykresie liczby logowań!
  * Wykrywa je jednak badanie **współczynnika zmienności czasów między zdarzeniami** ($CV = \frac{\sigma_{\tau}}{\mu_{\tau}} \approx 0$), test Kołmogorowa-Smirnowa odrzucający hipotezę o rozkładzie wykładniczym (proces Poissona) oraz **Szybka Transformata Fouriera (FFT)** i autokorelacja (**ACF**).

### Atak 3: Lateral Movement (Ruch boczny w sieci / Skanowanie SMB) – *Cel: Klastrowanie, Isolation Forest i Analiza Grafowa*
* **Koncepcja:** Drugie przejęte konto (`U_compromised_2`) wyrusza na rekonesans wewnątrz sieci, logując się kaskadowo na kilkadziesiąt różnych stacji roboczych i serwerów, na których nigdy wcześniej się nie logowało.
* **Reprezentacja w `auth.txt`:**
  * Czas: okno $30\text{ minut}$, około $150 \text{ -- } 250$ zdarzeń.
  * Sekwencja kaskadowa (łańcuch): `C_start` $\rightarrow$ `C_hop1` $\rightarrow$ `C_hop2` $\rightarrow$ logowania na grupę $35$ unikalnych komputerów `C_target_1 ... C_target_35` przy użyciu `Negotiate` / `NTLM`, `Network`, `LogOn`.
* **Jaki ślad zostawia (nasze uzasadnienie do raportu):**
  * W przestrzeni cech użytkowników (liczba unikalnych komputerów, entropia komputerów docelowych, stopień wyjściowy wierzchołka w grafie) konto `U_compromised_2` odrywa się od klastra normalnych pracowników i zostaje jednoznacznie oflagowane przez **Isolation Forest**, **LOF** oraz **DBSCAN** (jako punkt szumu `-1`).

---

## 4. Zasady Kamuflażu (OPSEC) – Jak nie ułatwić zadania drugiej grupie?

Podczas generowania pliku dla drugiej grupy nasz skrypt musi automatycznie zadbać o 5 detali technicznych:
1. **Prawdziwe identyfikatory z wycinka:** Nie wpisujemy ręcznie `U999999` ani `C_HACKER`. Skrypt najpierw skanuje nasz wycinek i wybiera istniejące w nim konta oraz komputery o przeciętnej aktywności.
2. **Zasada `Fail` w LANL:** W danych LANL status `Fail` mogą mieć tylko użytkownicy, którzy w zbiorze mają chociaż jedno `Success`. Nasz generator losuje ofiary Password Sprayingu wyłącznie z listy użytkowników posiadających udane logowania w wycinku.
3. **Pary `LogOn` / `LogOff` i typy uwierzytelniania:** Zdarzenia sieciowe w LANL mają określone kombinacje pól (np. `Kerberos,Network,LogOn,Success` lub `NTLM,Network,LogOn,Success`). Generator musi kopiować dokładne szablony wierszy z oryginalnego zbioru.
4. **Sortowanie po kolumnie `time`:** Po dodaniu naszych wierszy cały wycinek jest sortowany stabilnie po kolumnie `time` rosnąco.
5. **Identyczne formatowanie CSV:** Brak nagłówków (lub nagłówek tylko jeśli tak ustalicie z drugą grupą), ten sam znak końca linii (`\n`) i brak dodatkowych spacji.

---

## 5. Plan Pracy w Antigravity (Krok po Kroku na teraz)

1. **Krok 1 – Ekstrakcja wycinka (`src/slicer.py`):**
   * Pobranie pliku `auth.txt.gz` ze strony LANL do folderu `data/raw_lanl/`.
   * Uruchomienie skryptu wycinającego np. $450\,000$ wierszy z czystego okna czasowego (Doba 1, $t < 150\,000$) do pliku `data/raw_slice/auth_clean_slice.csv`.
2. **Krok 2 – Analiza tła (`src/eda_baseline.py`):**
   * Wygenerowanie statystyk wycinka: ilu jest użytkowników, ile komputerów, jak wygląda wykres aktywności w czasie, które konta nadają się na „ofiary” i „atakujących”.
3. **Krok 3 – Wstrzyknięcie ataków (`src/attack_injector.py`):**
   * Wygenerowanie i wplecenie 3 opisanych wyżej ataków.
   * Zapisanie pliku wynikowego `data/modified_for_enemy/auth_modified.csv` (gotowego do wysłania drugiej parze).
   * Zapisanie tajnego pliku `data/secret_ground_truth/manifest.json` z dokładnymi indeksami wierszy, czasami i parametrami naszych ataków.
4. **Krok 4 – Walidacja własna (`src/self_validator.py`):**
   * Uruchomienie na naszym zmodyfikowanym pliku algorytmów ZTKIK (Entropia, Z-score na szeregu czasowym, FFT/ACF, Isolation Forest, DBSCAN).
   * Wygenerowanie wykresów potwierdzających, że wszystkie 3 ataki dają się wykryć obliczeniowo. Te wykresy i obliczenia posłużą Wam od razu do pierwszej części sprawozdania (opisującej jak zaprojektowaliście i zweryfikowaliście symulację)!