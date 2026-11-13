# Proces Myślowy i Ścieżka Śledcza (Reasoning) – Etap 2: Odkrywanie Ataków Grupy Przeciwnej (Blue Team)

Dokument opisuje krok po kroku pełne śledztwo analityczne i kryptoanalityczne przeprowadzone na pliku otrzymanym od grupy przeciwnej: `data/received_from_enemy/lanl-auth-dataset-advanced-attacked` ($1.60\text{ GB}$, $75\,868\,965$ wierszy). Pokazuje dokładnie, co sprawdzaliśmy po kolei, jakie hipotezy stawialiśmy i jak odkryliśmy wszystkie 4 scenariusze ataków ($117$ wstrzykniętych rekordów) oraz dokładny algorytm użyty przez przeciwników.

---

## Krok 1: Wstępny rekonesans pliku (`head` / `tail`) i identyfikacja zbioru bazowego

### Co sprawdziliśmy na starcie?
Odczytaliśmy pierwsze 20 oraz ostatnie 20 linii pliku `data/received_from_enemy/lanl-auth-dataset-advanced-attacked`:
* **Pierwsze wiersze:**
  ```
  12096001,U1,C1171
  12096001,U3284,C3673
  12096001,U8867,C82
  ```
* **Ostatnie wiersze:**
  ```
  14515200,U12,C364
  14515200,U10332,C128
  14515200,U10332,C101
  ```

### Co z tego wywnioskowaliśmy?
1. Zbiór ma 3 kolumny bez nagłówka (`time,user,computer`) zgodne z opisem zbioru **LANL *"User-Computer Authentication Associations in Time"*** ($11\,362$ użytkowników `U1..U11362`, $22\,284$ komputery `C1..C22284`).
2. Znacznik początkowy to $t_{\min} = 12\,096\,001 = 140 \times 86\,400 + 1$ (początek Dnia 141), a znacznik końcowy to $t_{\max} = 14\,515\,200 = 168 \times 86\,400$ (koniec Dnia 168).
3. Różnica czasu wynosi dokładnie:
   $$\Delta T = 14\,515\,200 - 12\,096\,001 + 1 = 2\,419\,200\text{ s} = 28\text{ dób (4 pełne tygodnie)}$$
   Oznacza to, że grupa przeciwna pobrała **6. miesięczną paczkę (`lanl-auth-dataset-1-05`)** oryginalnego zbioru LANL i wstrzyknęła swoje ataki bezpośrednio do pełnego pliku miesięcznego o wielkości $1.6\text{ GB}$!

---

## Krok 2: Problem skali ($75.87\text{ mln}$ wierszy) – budowa binarnego cache'u NumPy i kontrola OPSEC

### Dlaczego nie analizowaliśmy pliku bezpośrednio w `pandas`?
Wielokrotne wczytywanie pliku CSV o wielkości $1.6\text{ GB}$ ($75.87\text{ mln}$ wierszy tekstu) przy każdym teście zajmowałoby za każdym razem ok. $4\text{ minuty}$ i kilkanaście gigabajtów pamięci RAM.

### Co zrobiliśmy (`src/enemy_ingest.py`)?
Napisaliśmy strumieniowy skrypt parsujący plik w blokach po $5\,000\,000$ wierszy (silnik C w `pandas`), który podczas jednego przebiegu ($253\text{ s}$):
1. Odciął prefiksy `'U'` oraz `'C'` i zapisał trzy płaskie tablice binarne 32-bitowych liczb całkowitych (`int32`) do `data/received_from_enemy/cache/`:
   * `time.npy` ($303\text{ MB}$)
   * `uid.npy` ($303\text{ MB}$)
   * `cid.npy` ($303\text{ MB}$)
   Dzięki temu każde kolejne zapytanie na pełnych $75\,868\,965$ wierszach ładowaliśmy przez `np.load(..., mmap_mode='r')` w **$0.05\text{ sekundy}$**!
2. Jednocześnie skrypt sprawdził 3 potencjalne błędy OPSEC:
   * Czy istnieją błędnie sformatowane linie lub puste wartości? $\rightarrow$ `0` (brak).
   * Czy grupa przeciwna dodała identyfikatory spoza oficjalnej specyfikacji LANL (`uid > 11362` lub `cid > 22284`)? $\rightarrow$ `0` (zakres w pliku to `U1..U10654` oraz `C1..C19794`).
   * **Czy kolumna `time` jest ściśle niemalejąca ($t_{i-1} \le t_i$)?** $\rightarrow$ **TRAFIENIE!** Skrypt natychmiast zaraportował naruszenia monotoniczności czasu!

---

## Krok 3: Pierwszy trop kryminalistyczny – analiza naruszeń monotoniczności czasu

W podsumowaniu `ingest_meta.json` zobaczyliśmy pierwsze próbki miejsc, gdzie czas cofał się względem poprzedniego wiersza (`t[i] < t[i-1]`):
```
row:   5000, prev_time: 12096221, curr_time: 12096001
row:  20005, prev_time: 12096847, curr_time: 12096001
row:  35010, prev_time: 12097457, curr_time: 12096001
row:  50015, prev_time: 12098095, curr_time: 12096001
row:  65020, prev_time: 12098727, curr_time: 12096001
row:  80025, prev_time: 12099373, curr_time: 12096101
row: 100028, prev_time: 12100205, curr_time: 12096101
row: 120031, prev_time: 12101022, curr_time: 12096101
row: 140034, prev_time: 12101870, curr_time: 12096101
row: 160038, prev_time: 13096000, curr_time: 12102737
...
row: 250057, prev_time: 13316401, curr_time: 12106619
```

### Co natychmiast rzuciło nam się w oczy?
1. Spójrz na numery wierszy (`row`):
   * `5000` (wstawiono 5 wierszy $\rightarrow$ przesunięcie o $+5$)
   * `20005` ($20000 + 5$, wstawiono 5 wierszy $\rightarrow$ przesunięcie o $+10$)
   * `35010` ($35000 + 10$, wstawiono 5 wierszy $\rightarrow$ przesunięcie o $+15$)
   * `50015` ($50000 + 15$, wstawiono 5 wierszy $\rightarrow$ przesunięcie o $+20$)
   * `65020` ($65000 + 20$, wstawiono 5 wierszy $\rightarrow$ przesunięcie o $+25$)
   * `80025` ($80000 + 25$, wstawiono 3 wiersze $\rightarrow$ przesunięcie o $+28$)
   * `100028` ($100000 + 28$, wstawiono 3 wiersze $\rightarrow$ przesunięcie o $+31$)
   * `120031` ($120000 + 31$, wstawiono 3 wiersze $\rightarrow$ przesunięcie o $+34$)
   * `140034` ($140000 + 34$, wstawiono 3 wiersze $\rightarrow$ przesunięcie o $+37$)
   * `160037` ($160000 + 37$, wstawiono 1 wiersz z czasem `13096000` $\rightarrow$ przesunięcie o $+38$)

2. **Dlaczego próba z naiwnym `running_max = np.maximum.accumulate(t)` zwróciła $34.8\text{ mln}$ wierszy?**
   * Ponieważ w wierszu `160037` grupa przeciwna wstrzyknęła pojedynczy rekord z czasem z przyszłości (`t = 13096000`, czyli $+993\,264\text{ s} \approx +11.5\text{ doby}$ do przodu względem bieżącego czasu tła `12102736`)! Przez to maksimum kroczące (`running_max`) podskoczyło do `13096000`, oznaczając kolejne $34.8\text{ mln}$ normalnych wierszy jako mniejsze od maksimum!

---

## Krok 4: Zastosowanie śledzenia monotonicznego tła (`bg_t`) i wyłuskanie wszystkich 117 wierszy

### Jak rozwiązaliśmy problem skoków w przód i w tył?
Wiedzieliśmy, że w oryginalnym zbiorze LANL jest średnio $\sim 31$ zdarzeń na sekundę, więc między kolejnymi oryginalnymi wierszami czas rośnie o $0\text{ s}$ lub $1\text{ s}$ (maksymalnie $2\text{ s}$ w nocy).
Zaimplementowaliśmy zachłanny detektor monotonicznego tła na całej tablicy $75\,868\,965$ wierszy:
```python
bg_t = t[0]
injected = []
for i in range(len(t)):
    if 0 <= t[i] - bg_t <= 5:
        bg_t = t[i]
    else:
        injected.append((i, int(t[i]), int(u[i]), int(c[i]), int(bg_t)))
```

### Wynik na całym zbiorze $75\,868\,965$ wierszy:
Skrypt wyłuskał **dokładnie $117$ wstrzykniętych wierszy** i po odjęciu skumulowanego przesunięcia (`orig_line = i - len(injected_so_far)`) odsłonił **4 kompletne scenariusze ataków**:

1. **Grupa 1 (`orig_line` = `5000, 20000, 35000, 50000, 65000` — odpowiednik `range(5000, 80000, 15000)`):**
   * 5 użytkowników: `U8693`, `U3120`, `U3254`, `U257`, `U9517`.
   * Każdy wykonuje dokładnie 5 logowań w chwilach `t = 12096001, 12096003, 12096005, 12096007, 12096009` (krok $\Delta t = 2\text{ s}$, $CV = 0.0$) na 5 różnych komputerów ($25$ wierszy).
2. **Grupa 2 (`orig_line` = `80000, 100000, 120000, 140000` — odpowiednik `range(80000, 160000, 20000)`):**
   * 4 użytkowników: `U7321`, `U1789`, `U396`, `U1062`.
   * Każdy wykonuje 3 logowania w identycznych chwilach `t = 12096101, 12096109, 12096116` (odstępy $8\text{ s}$ i $7\text{ s}$) na 3 różne komputery ($12$ wierszy).
   * *Ciekawostka śledcza:* Dlaczego w Grupie 2 są 4 konta, a w pozostałych po 5? Ponieważ w Pythonie `range(80000, 160000, 20000)` generuje 4 wartości (`80000, 100000, 120000, 140000`), gdyż górna granica `160000` jest wyłączona (i od `160000` zaczyna się już Grupa 3!).
3. **Grupa 3 (`orig_line` = `160000, 175000, 190000, 205000, 220000` — odpowiednik `range(160000, 235000, 15000)`):**
   * 5 użytkowników: `U711 -> C16153`, `U337 -> C521`, `U4077 -> C857`, `U2851 -> C1296`, `U1456 -> C16907`.
   * Pojedyncze zdarzenia w chwilach `t = 13096000, 13099600, 13103200, 13106800, 13110400` — idealnie co $\Delta t = 3\,600\text{ s}$ ($1\text{ godzina}$, $CV = 0.0$, $5$ wierszy).
4. **Grupa 4 (`orig_line` = `250000, 260000, 270000, 280000, 290000` — odpowiednik `range(250000, 300000, 10000)`):**
   * 5 użytkowników: `U24`, `U2867`, `U7230`, `U9578`, `U972`.
   * Każdy użytkownik wykonuje serię **15 połączeń przez 15 kolejnych dób** w odstępach **$\Delta t = 86\,400\text{ s}$ ($24\text{ h}$, $CV = 0.0$)** na 15 różnych komputerów ($75$ wierszy).
   * Co więcej, czasy startowe kolejnych 5 kont to: `12106801`, `12107101`, `12107401`, `12107701`, `12108001` – są przesunięte względem siebie w fazie dokładnie o **$\Delta \phi = 300\text{ s}$ ($5\text{ minut}$)**!

---

## Krok 5: Weryfikacja hipotez alternatywnych – czy w pliku ukryto jeszcze jakieś ataki „posortowane”?

Jako dobry zespół Blue Team nie poprzestaliśmy na złapaniu 117 nieposortowanych wierszy – postawiliśmy pytanie: *„A co jeśli grupa przeciwna wstrzyknęła jeszcze jakiś 5. atak, w którym dopasowała czas `t` do bieżącego czasu linii lub dopisała go w posortowanym miejscu?”*

Przeprowadziliśmy 4 rygorystyczne testy sprawdzające cały zbiór $75\,868\,965$ wierszy:

### Test A: Matematyczna kontrola przesunięcia indeksów przed linią `250,000`
* Suma wierszy z Grup 1, 2 i 3 wynosi $25 + 12 + 5 = 42$.
* Pierwszy wiersz Grupy 4 wypadł dokładnie na indeksie `250,042` ($250\,042 - 42 = 250\,000$).
* **Wniosek:** Pomiędzy linią `1` a linią `250,000` nie został wstawiony ani jeden dodatkowy wiersz (nawet taki, który miałby zgodny czas `t`), bo przesunąłby on start Grupy 4 na $\ge 250\,043$!

### Test B: Inspekcja wielokrotności linii po `290,000` (`300k, 305k, 310k, 320k, 350k, 400k, 500k`) oraz ciągów tego samego użytkownika
* Sprawdziliśmy wszystkie miejsca w całym pliku $75.87\text{ mln}$ wierszy, gdzie ten sam użytkownik występuje w sąsiednich wierszach ze zmieniającym się czasem (`u[i] == u[i+1]` oraz `t[i] != t[i+1]`), oraz wszystkie ciągi $\ge 12$ wierszy tego samego użytkownika lub $\ge 15$ wierszy tego samego komputera.
* **Wynik:** Po wierszu `290,116` w całym pliku nie występuje już ani jedna wielowierszowa seria ze zmieniającym się czasem! Wszystkie inne długie serie tego samego użytkownika (np. `U5580`, `U4258`) lub komputera (`C443`, `C209`) mają miejsce w obrębie tej samej pojedynczej sekundy i dotyczą stałej puli komputerów serwerowych.

### Test C: Analiza pików wolumetrycznych w całym 28-dniowym szeregu czasowym
* Zliczyliśmy zdarzenia w każdej z $2\,419\,200$ sekund oraz każdej z $40\,320$ minut miesiąca.
* Zbadaliśmy największe piki minutowe (np. $t \in [13\,633\,500, 13\,634\,100]$, $t \in [12\,419\,800, 12\,420\,100]$ oraz $t \in [14\,432\,450, 14\,432\,520]$).
* Okazało się, że w tych oknach dominują konta `U12`, `U13`, `U4059` łączące się tysiące razy z głównymi serwerami `C670`, `C148`, `C200`, `C151` – są to naturalne procesy wsadowe obecne przez cały miesiąc w zbiorze LANL.

### Test D: Analiza częstości par `(user, computer)` w skali całego miesiąca (*Singleton Edges*)
* Dla każdego z 19 wykrytych kont sprawdziliśmy, ile razy w całym 28-dniowym zbiorze ($75\,868\,965$ wierszy) wystąpiły ich połączenia z komputerami ze wstrzykniętych wierszy:
  ```
  U   24: inj_comps=15, counts_in_whole_month=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  U  972: inj_comps=15, counts_in_whole_month=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  U 2867: inj_comps=15, counts_in_whole_month=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  U 7230: inj_comps=15, counts_in_whole_month=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  U 9578: inj_comps=15, counts_in_whole_month=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  ```
* **Kluczowe odkrycie:** Wszystkie 117 wstrzykniętych wierszy ma krotność równą dokładnie `1` w skali całego miesiąca! Normalny użytkownik w LANL loguje się wielokrotnie na swoje stałe komputery (setki lub tysiące razy w miesiącu), natomiast generator grupy przeciwnej losował numery komputerów `C<losowy>`, tworząc jednorazowe krawędzie w grafie dwudzielnym `User-Computer`.

---

## Krok 6: Formalne udowodnienie wykrywalności metodami ZTKIK (`src/enemy_analyzer.py`)

Aby raport spełniał wszystkie wymagania merytoryczne przedmiotu ZTKIK, w module `src/enemy_analyzer.py` połączyliśmy dowód kryminalistyczny z pełnym aparatem matematycznym:
1. **Szeregi czasowe i FFT:** Wyznaczyliśmy widmo mocy FFT dla 28-dniowego szeregu godzinowego (potwierdzając dominujący cykl dobowy $T = 24.00\text{ h}$) oraz pokazaliśmy synchroniczną koincydencję czasową Scenariusza 1 ($\Delta t = 2\text{ s}$) i Scenariusza 2 ($\Delta t \in \{8, 7\}\text{ s}$).
2. **Rozkłady IAT, $CV$, test Kołmogorowa-Smirnowa i ACF:** Dla botów ze Scenariusza 4 ($T = 86\,400\text{ s}$, $\Delta \phi = 300\text{ s}$) wykazaliśmy $CV = 0.0000$, odrzuciliśmy hipotezę o rozkładzie wykładniczym (procesie Poissona) testem Kołmogorowa-Smirnowa ($D_{\text{KS}} = 0.6321$, $p = 1.23 \times 10^{-27}$) oraz wyznaczyliśmy piki autokorelacji $\text{ACF}(24\text{h}) = 0.9332$, $\text{ACF}(48\text{h}) = 0.8665$, $\text{ACF}(72\text{h}) = 0.7997$.
3. **Entropia Shannona, Grafy i Machine Learning (`IsolationForest`, `LOF`, `DBSCAN`, `PCA 2D`):** Zbudowaliśmy wektor cech dla wszystkich $10\,138$ użytkowników (uwzględniający m.in. liczbę połączeń jednorazowych `singleton_computers`, `singleton_ratio`, entropię $H(C \mid U)$ oraz odchylenie strumienia) i wykazaliśmy na rzutowaniu PCA 2D oraz w tabeli wyników, że wszystkie 19 kont z 4 scenariuszy zostaje jednoznacznie odseparowane od tła (`DBSCAN = -1`, wysokie wyniki `IForest` i `LOF`).

