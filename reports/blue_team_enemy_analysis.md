# Raport Blue Team: Kryptoanaliza Statystyczna i Detekcja Ataków w Zbiorze Grupy Przeciwnej (Etap 2 – ZTKIK)

## 1. Charakterystyka Otrzymanego Zbioru Danych

Grupa przeciwna przekazała zmodyfikowany plik `data/received_from_enemy/lanl-auth-dataset-advanced-attacked` bazujący na 3-kolumnowym zbiorze **LANL *"User-Computer Authentication Associations in Time"* (`time,user,computer`)**:

| Parametr Zbioru | Wartość |
| :--- | :--- |
| **Format rekordu** | `time,user,computer` (3 kolumny, brak nagłówka, rozdzielane przecinkiem) |
| **Rozmiar pliku** | $1.60\text{ GB}$ ($1\,601\,949\,660\text{ bajtów}$) |
| **Całkowita liczba wierszy w pliku** | **$75\,868\,965$** |
| **Oryginalna liczba wierszy tła (Miesiąc 6 LANL)** | $75\,868\,848$ |
| **Wykryta liczba wstrzykniętych wierszy ataków** | **$117$ wierszy** ($4$ odrębne scenariusze ataków, $19$ kont użytkowników) |
| **Przedział czasowy zbioru** | $t \in [12\,096\,001\text{ s},\; 14\,515\,200\text{ s}]$ (dokładnie $28\text{ dób} = 2\,419\,200\text{ s}$, Doby $141\text{--}168$) |
| **Liczba unikalnych użytkowników** | $10\,138$ (zakres `U1` .. `U10654` $\subset [1, 11\,362]$) |
| **Liczba unikalnych komputerów** | $14\,940$ (zakres `C1` .. `C19794` $\subset [1, 22\,284]$) |
| **Dominujący okres w widmie FFT tła** | $T_{\text{FFT}} = 24.00\text{ h}$ (silny cykl dobowy $24\text{ h}$ oraz tygodniowy) |

---

## 2. Główny Przełom Kryminalistyczny: Rekonstrukcja Generatora Przeciwników

W oryginalnym zbiorze LANL znaczniki czasu są **ściśle niemalejące** ($t_1 \le t_2 \le \dots \le t_N$). Ponieważ plik liczy ponad $75.8\text{ mln}$ wierszy ($1.6\text{ GB}$), grupa przeciwna użyła skryptu strumieniowego, który **wstrzykiwał spreparowane zdarzenia w dokładnych wielokrotnościach numeru linii (`orig_line`) bez ponownego posortowania pliku wynikowego po kolumnie `time`**!

Co więcej, **wszystkie $117$ wstrzykniętych zdarzeń tworzy tzw. krawędzie jednorazowe (*singleton edges*)** – żadna z $117$ par `(user, computer)` użytych w ataku nie pojawia się ani razu w pozostałych $75\,868\,848$ wierszach całego miesiąca!

Pozwoliło to na **100% bezbłędną rekonstrukcję dokładnych pętli `range()` z kodu źródłowego grupy przeciwnej**:

| Scenariusz Ataku | Zrekonstruowany Wyzwalacz Linii (`orig_line`) | Liczba Kont $\times$ Zdarzeń | Przesunięcie Indeksu Wierszy | Charakterystyka Matematyczna |
| :--- | :--- | :---: | :---: | :--- |
| **Scenariusz 1:** Szybki Ruch Boczny (*Rapid 5-Host Fan-out*) | `range(5000, 80000, 15000)`<br>(`5000, 20000, 35000, 50000, 65000`) | $5 \times 5 = 25$ | `+0` $\rightarrow$ `+25` | $\Delta t = 2.0\text{ s}$ ($CV = 0.0$), synchroniczne okno $t \in [12096001, 12096009]$, $5$ obcych hostów/konto ($H = 2.3219\text{ b}$) |
| **Scenariusz 2:** Synchroniczna Kaskada Rozpoznawcza (*3-Host Recon Burst*) | `range(80000, 160000, 20000)`<br>(`80000, 100000, 120000, 140000`) | $4 \times 3 = 12$ | `+25` $\rightarrow$ `+37` | $\Delta t \in \{8\text{ s}, 7\text{ s}\} \Rightarrow \mu_\tau = 7.5\text{ s}, CV = 0.0667$, identyczne chwile $t \in \{12096101, 12096109, 12096116\}$ |
| **Scenariusz 3:** Rozproszony Beaconing Godzinowy (*Distributed Hourly Stepping*) | `range(160000, 235000, 15000)`<br>(`160000, 175000, 190000, 205000, 220000`) | $5 \times 1 = 5$ | `+37` $\rightarrow$ `+42` | Idealny krok godzinowy $\Delta t = 3\,600\text{ s}$ ($1\text{ h}, CV = 0.0$), $t_k = 13\,096\,000 + k \cdot 3600$ ($k=0\dots 4$) |
| **Scenariusz 4:** Długoterminowy Dobowy Beaconing C2 (*24h Persistence Botnet*) | `range(250000, 300000, 10000)`<br>(`250000, 260000, 270000, 280000, 290000`) | $5 \times 15 = 75$ | `+42` $\rightarrow$ `+117` | Idealny okres dobowy $T = 86\,400\text{ s}$ ($24\text{ h}, CV = 0.0$) przez $15\text{ dób}$, przesunięcie fazowe między 5 botami $\Delta \phi = 300\text{ s}$ ($5\text{ min}$) |

> **Dowód kompletności:** Przed linią `250,000` suma wstrzykniętych wierszy ze Scenariuszy 1–3 wynosi dokładnie $25 + 12 + 5 = 42$. Pierwszy wiersz Scenariusza 4 wypada w pliku dokładnie pod indeksem `250,042` ($250\,000 + 42$), a po wierszu `290,116` ($290\,000 + 117$) aż do końca pliku ($75\,868\,965$) nie występuje już ani jedno naruszenie monotoniczności.

![Szereg czasowy 28 dni i dowód kryminalistyczny](figures/enemy_fig1_forensic_timeline_and_jumps.png)

---

## 3. Szczegółowa Dokumentacja 4 Wykrytych Scenariuszy Ataków

### 3.1. Scenariusz 1: Szybki Ruch Boczny / Skanowanie Wielu Hostów (25 zdarzeń)

Pięć przejętych kont użytkowników wykonuje w ciągu pierwszych $8\text{ sekund}$ zbioru ($t \in [12\,096\,001,\; 12\,096\,009]$) serię $5$ szybkich logowań co dokładnie $\Delta t = 2\text{ s}$ ($CV = 0.0000$) na $5$ różnych komputerów docelowych:

| Użytkownik | Wyzwalacz `orig_line` | Zakres wierszy w pliku | Znaczniki czasu `time` [s] | Sekwencja $5$ atakowanych komputerów (100% singleton pairs) | Entropia w oknie ataku $H(C \mid U)$ |
| :--- | :---: | :---: | :---: | :--- | :---: |
| `U8693` | `5000` | `5000..5004` | `12096001..12096009` (krok $2\text{ s}$) | `C3930, C12820, C1503, C18078, C18017` | $2.3219\text{ b}$ |
| `U3120` | `20000` | `20005..20009` | `12096001..12096009` (krok $2\text{ s}$) | `C2123, C2291, C10823, C3456, C7256` | $2.3219\text{ b}$ |
| `U3254` | `35000` | `35010..35014` | `12096001..12096009` (krok $2\text{ s}$) | `C3613, C6805, C1096, C4064, C1125` | $2.3219\text{ b}$ |
| `U257` | `50000` | `50015..50019` | `12096001..12096009` (krok $2\text{ s}$) | `C1225, C17759, C2321, C1815, C2854` | $2.3219\text{ b}$ |
| `U9517` | `65000` | `65020..65024` | `12096001..12096009` (krok $2\text{ s}$) | `C13948, C479, C16642, C15792, C481` | $2.3219\text{ b}$ |

---

### 3.2. Scenariusz 2: Skoordynowana Kaskada Rozpoznawcza (12 zdarzeń)

Cztery przejęte konta wykonują w oknie $t \in [12\,096\,101,\; 12\,096\,116]$ synchroniczne trójki logowań dokładnie w tych samych sekundach (`12096101`, `12096109`, `12096116`, czyli $\Delta t_1 = 8\text{ s}, \Delta t_2 = 7\text{ s}$, $\mu_\tau = 7.5\text{ s}, CV = 0.0667$):

| Użytkownik | Wyzwalacz `orig_line` | Zakres wierszy w pliku | Znaczniki czasu `time` [s] | Sekwencja $3$ atakowanych komputerów (100% singleton pairs) | Entropia w oknie ataku $H(C \mid U)$ |
| :--- | :---: | :---: | :---: | :--- | :---: |
| `U7321` | `80000` | `80025..80027` | `12096101, 12096109, 12096116` | `C7286, C4747, C5488` | $1.5850\text{ b}$ |
| `U1789` | `100000` | `100028..100030` | `12096101, 12096109, 12096116` | `C14179, C1614, C4435` | $1.5850\text{ b}$ |
| `U396` | `120000` | `120031..120033` | `12096101, 12096109, 12096116` | `C1694, C16272, C9276` | $1.5850\text{ b}$ |
| `U1062` | `140000` | `140034..140036` | `12096101, 12096109, 12096116` | `C4552, C2836, C5461` | $1.5850\text{ b}$ |

---

### 3.3. Scenariusz 3: Rozproszony Beaconing Godzinowy ze Zmianą Tożsamości (5 zdarzeń)

Pięć kont wykonuje pojedyncze logowania na losowe, nigdy wcześniej nieużywane komputery w Dniu 12 wycinka, w idealnych odstępach **$\Delta t = 3\,600\text{ s}$ ($1\text{ godzina}$, $CV = 0.0000$)**:

| Krok $k$ | Użytkownik | Komputer docelowy | Wyzwalacz `orig_line` | Indeks wiersza w pliku | Znacznik czasu `time` [s] | Odstęp $\Delta t$ od poprzedniego kroku |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| $k=0$ | `U711` | `C16153` | `160000` | `160037` | `13096000` | — (Start serii) |
| $k=1$ | `U337` | `C521` | `175000` | `175038` | `13099600` | $+3\,600\text{ s}$ ($1.00\text{ h}$) |
| $k=2$ | `U4077` | `C857` | `190000` | `190039` | `13103200` | $+3\,600\text{ s}$ ($1.00\text{ h}$) |
| $k=3$ | `U2851` | `C1296` | `205000` | `205040` | `13106800` | $+3\,600\text{ s}$ ($1.00\text{ h}$) |
| $k=4$ | `U1456` | `C16907` | `220000` | `220041` | `13110400` | $+3\,600\text{ s}$ ($1.00\text{ h}$) |

---

### 3.4. Scenariusz 4: Długoterminowy Dobowy Beaconing C2 / Persistence (75 zdarzeń)

Najbardziej rozbudowany atak w zbiorze: **5 przejętych kont użytkowników** przez **15 kolejnych dób** wykonuje punktualnie jedno połączenie na dobę (**okres $T = 86\,400\text{ s} = 24\text{ h}$, odchylenie $\sigma_\tau = 0\text{ s}$, współczynnik zmienności $CV = 0.0000$**), za każdym razem łącząc się z nowym komputerem docelowym (`15` unikalnych maszyn na każde konto = `75` maszyn łącznie).

Dodatkowo boty są zsynchronizowane w łańcuchu fazowym przesuniętym dokładnie o **$\Delta \phi = 300\text{ s}$ ($5\text{ minut}$)**:

| Użytkownik | Wyzwalacz `orig_line` | Zakres wierszy w pliku | Wzór czasu $t_k$ ($k = 0 \dots 14$) | Liczba cykli (dób) | Lista $15$ atakowanych komputerów (po $1$ na każdą dobę) |
| :--- | :---: | :---: | :--- | :---: | :--- |
| `U24` | `250000` | `250042..250056` | $12106801 + k \cdot 86\,400\text{ s}$ (faza $+0\text{ min}$) | $15$ | `C443, C4539, C5466, C1024, C1273, C788, C1773, C5623, C456, C1381, C3710, C1170, C8920, C7785, C8389` |
| `U2867` | `260000` | `260057..260071` | $12107101 + k \cdot 86\,400\text{ s}$ (faza $+5\text{ min}$) | $15$ | `C9375, C1047, C488, C984, C9190, C5982, C3323, C11024, C14872, C9745, C15412, C3285, C2248, C2336, C4642` |
| `U7230` | `270000` | `270072..270086` | $12107401 + k \cdot 86\,400\text{ s}$ (faza $+10\text{ min}$) | $15$ | `C9148, C13781, C15541, C3854, C13235, C568, C72, C5467, C12406, C8019, C4990, C4352, C993, C848, C3477` |
| `U9578` | `280000` | `280087..280101` | $12107701 + k \cdot 86\,400\text{ s}$ (faza $+15\text{ min}$) | $15$ | `C3083, C5178, C7286, C1410, C551, C2032, C235, C3397, C1556, C5623, C15765, C294, C4747, C6629, C8` |
| `U972` | `290000` | `290102..290116` | $12108001 + k \cdot 86\,400\text{ s}$ (faza $+20\text{ min}$) | $15$ | `C1467, C2898, C4375, C33, C17646, C1610, C5202, C1971, C615, C2064, C1126, C2354, C638, C15979, C9348` |

#### Dowody statystyczne i widmowe dla Scenariusza 4:
* **Współczynnik zmienności IAT:** $CV = \frac{\sigma_\tau}{\mu_\tau} = \frac{0}{86\,400} = 0.0000 \ll 1$.
* **Test zgodności Kołmogorowa-Smirnowa przeciwko rozkładowi wykładniczemu $\text{Exp}(\lambda = 1/86\,400\text{ s})$:**
  * Dla pojedynczego konta ($n = 14$ odstępów dobowych): **$D_{\text{KS}} = 0.6321$**, **$p\text{-value} = 5.967e-06$**.
  * Dla połączonej puli 5 botów ($n = 70$ odstępów dobowych): **$D_{\text{KS}} = 0.6321$**, **$p\text{-value} = 1.234e-27$** (całkowite odrzucenie hipotezy o naturalnym procesie Poissona).
* **Funkcja Autokorelacji (ACF):**
  * Sygnał zbiorczy wykazuje idealne piki okresowe w wielokrotnościach doby: $\text{ACF}(24\text{ h}) = 0.9332$, $\text{ACF}(48\text{ h}) = 0.8665$, $\text{ACF}(72\text{ h}) = 0.7997$.

![Analiza IAT, test KS oraz ACF dla Scenariusza 4](figures/enemy_fig2_periodic_beacons_iat_acf.png)

---

## 4. Wielowymiarowa Detekcja ML (Isolation Forest, LOF, DBSCAN, PCA 2D) i Analiza Grafowa

Dla wszystkich $10,138$ aktywnych użytkowników w 28-dniowym zbiorze obliczono 6-wymiarowy wektor cech behawioralnych, obejmujący m.in.: całkowitą liczbę logowań, liczbę unikalnych komputerów, liczbę komputerów jednorazowych (`singleton_computers`), wskaźnik `singleton_ratio`, entropię Shannona komputerów docelowych $H(C \mid U)$ oraz maksymalną anomalię chronologii $\max |\Delta t|$.

### Tabela wszystkich 19 wykrytych kont biorących udział w atakach:

| Użytkownik | Przypisany Scenariusz Ataku | Liczba logowań (miesiąc) | Unikalne komputery | Komputery jednorazowe (`singleton`) | Entropia $H(C \mid U)$ [bity] | IForest Score | LOF Score | Klaster DBSCAN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `U8693` | `Scenario_1_Rapid_5Host_Fanout` | 118,114 | 74 | **10** | 1.6321 | **0.7189** | **6.4268** | `-1` |
| `U3120` | `Scenario_1_Rapid_5Host_Fanout` | 2,981 | 16 | **8** | 0.4243 | **0.7171** | **8.0789** | `-1` |
| `U3254` | `Scenario_1_Rapid_5Host_Fanout` | 2,770 | 11 | **6** | 0.8916 | **0.7115** | **8.0706** | `-1` |
| `U9517` | `Scenario_1_Rapid_5Host_Fanout` | 2,357 | 15 | **6** | 1.2988 | **0.6871** | **6.6459** | `-1` |
| `U257` | `Scenario_1_Rapid_5Host_Fanout` | 5,269 | 17 | **6** | 2.1078 | **0.6870** | **8.6911** | `-1` |
| `U1789` | `Scenario_2_Sync_3Host_Burst` | 6,644 | 80 | **3** | 5.5647 | **0.7189** | **5.9696** | `-1` |
| `U7321` | `Scenario_2_Sync_3Host_Burst` | 29,986 | 11 | **3** | 1.6546 | **0.6450** | **6.5564** | `-1` |
| `U396` | `Scenario_2_Sync_3Host_Burst` | 3,183 | 12 | **3** | 1.5838 | **0.6212** | **6.7063** | `-1` |
| `U1062` | `Scenario_2_Sync_3Host_Burst` | 4,381 | 14 | **3** | 1.8773 | **0.6208** | **6.8885** | `-1` |
| `U1456` | `Scenario_3_Hourly_Distributed_Beacon` | 101,842 | 15 | **1** | 1.4706 | **0.6451** | **8.2816** | `-1` |
| `U337` | `Scenario_3_Hourly_Distributed_Beacon` | 19,354 | 12 | **2** | 1.2390 | **0.6335** | **8.3079** | `-1` |
| `U4077` | `Scenario_3_Hourly_Distributed_Beacon` | 6,637 | 19 | **1** | 2.5932 | **0.6235** | **8.7330** | `-1` |
| `U711` | `Scenario_3_Hourly_Distributed_Beacon` | 15,485 | 13 | **1** | 1.5509 | **0.6128** | **9.6109** | `-1` |
| `U2851` | `Scenario_3_Hourly_Distributed_Beacon` | 3,030 | 21 | **1** | 1.3165 | **0.6096** | **9.6320** | `-1` |
| `U972` | `Scenario_4_Daily_24h_C2_Beaconing` | 4,890 | 17 | **15** | 0.0556 | **0.7709** | **5.0346** | `-1` |
| `U7230` | `Scenario_4_Daily_24h_C2_Beaconing` | 6,582 | 26 | **15** | 0.4750 | **0.7615** | **6.1542** | `-1` |
| `U24` | `Scenario_4_Daily_24h_C2_Beaconing` | 3,390 | 27 | **18** | 0.9766 | **0.7576** | **5.5027** | `-1` |
| `U9578` | `Scenario_4_Daily_24h_C2_Beaconing` | 2,977 | 23 | **15** | 1.1319 | **0.7507** | **5.4985** | `-1` |
| `U2867` | `Scenario_4_Daily_24h_C2_Beaconing` | 3,166 | 26 | **15** | 1.4873 | **0.7483** | **5.4964** | `-1` |

![Rzutowanie PCA 2D i Graf Dwudzielny](figures/enemy_fig3_ml_pca_and_bipartite_graph.png)
