# Statische Analyse mit Ghidra

Um den Binärcode zu und analysieren kommen RE-Tools wie Ghidra oder IDA Pro zum Einsatz.
Bis 2019 war **IDA Pro** das führende kommerzielle Tool für Reverse Engineering, jedoch mit hohen Lizenzkosten.  

**Ghidra** wurde von der NSA entwickelt und wurde erstmals 2019 der Öffentlichkeit vorgestellt und hatte sich schnell als Open-Source-Alternative etabliert. Anfangs nur als Binary verfügbar, wurde es später vollständig quelloffen, was das Vertrauen in die Software erhöhte.  
Heute gilt Ghidra als eines der leistungsfähigsten Tools zur statischen Analyse von Binaries.

Im folgenden werden die ersten Schritte mit Ghidra aufgezeigt. Als Hilfestellung wurde dazu ein [Startvideo](videos/02_create_project.mkv) zur Projekterstellung und ein [Navigationsvideo](videos/03_navigating_in_ghidra.mkv) aufgenommen.


## Navigation in Ghidra:
### 1. **Projekt erstellen & Binary importieren**  
Das ELF-Binary `vuln_noprot` wird als Analyseobjekt ausgewählt.


### 2. **Analyzefunktionen auswählen**  
Es gibt viele Analyzer (und Prototypen), mit denen das Binary analysiert werden kann.
Ghidra kann damit automatisch Funktionen, Labels, Strings und Referenzen erkennen. 
Diese Analyse kann jederzeit erneut ausgeführt werden bzw. für bestimmte Analyzer wiederholt werden.


### 3. **Assembler-Listing betrachten**  
Der mittlere Hauptbereich zeigt die dekodierten Assembler-Instruktionen auf Basis der Architektur (hier: x86, 32-Bit). Scrollt man ganz nach oben zum Anfang der Binary, dem Header-Bereich, sieht man schon die Magic Number "ELF", was die Linux ELF Binary kennzeichnet und weitere Informationen wie Dateityp (Executable), Architekturklasse (32-Bit), CPU-Typ (Intel 80386).


### 4. **Program Tree & Memory Map prüfen**  
Der Program Tree ermöglicht das gezielte Navigieren durch die Sections der Binary (z. B. `.text`, `.data`, `.rodata`) und die Zugriffsrechte (RWX) für die Segmente können in Ghidra unter `> Windows > Memory Map`angeschaut werden.


### 5. **Symbol Tree analysieren**  
Zeigt die Funktionen, Imports (z. B. `read`, `write`, `bind`) und Labels, die von den anfangs ausgewählten Analyzern identifiziert wurden. Besonders nützlich sind die direkt am Namen erkennbaren Funktionen wie `main` oder `secret`.
Diese Namen sind nur vorhanden, da die Binary `vuln_noprot` mit Debug-Informationen (mit .symtab) kompiliert wurde. 
Wie das ganze aussehen würde in einer stripped Binary ist in dem [Stripped Video](videos/05_stripped.mkv) zu sehen.



### 6. **Decompile-View nutzen**  
Der Decompiler (im Video rechts) ist das mächtigste Feature Ghidra's, da es den rekonstruierten lesbaren C-Pseudocode zeigt.
Ghidra unterstützt viele Architekturen (Assemblersprachen) und ist in der Lage diese architektur-spezifischen Maschinenbefehle in der Binary durch entsprechende Disassemblern in  **Assembler-Listing** umzuwandeln. 
Ghidra nutzt als Zwischensprache den internen P-Code, der erst diese architektur-spezifischen Assembler-Listings in P-Code Instruktionen umwandelt und dann daraus einen lesbaren, **C-ähnlichen Pseudocode** generiert. Dadurch können Funktionen identifiziert, Kontrollflüsse rekonstruiert und sogar die Logik des Programms verstanden werden, ohne Zugriff auf den Originalquellcode.


---


## Analyse von `vuln_noprot`
Die Analyse der Binary `examples/vuln_server/binaries/vuln_norot` wird im [diesem Video gezeigt](videos/04_finding_buffer_overflow.mkv).


### Start - Main
Per Symbol Tree kann leicht zur Start-Funktion, der `main` navigiert werden.
Im Decompile-Fenster lassen sich anhand der Funktionsaufrufe wie `socket`, `bind`, `listen`, `accept` bereits erste Hinweise auf den Verbindungsaufbau erkennen.


### Rename & Analyse  
Um Übersicht zu gewinnen, können Variablen und Funktionen umbenannt werden.  
Beispielsweise ist der Rückgabewert von `accept` zunächst als `local_18` benannt. Wird dieser innerhalb der Funktion `handle_client` verwendet, kann er sinnvoll z. B. als `client_fd` benannt werden. Diese Änderung wirkt sich global im erstellten Projekt aus.


### Programmflow nachvollziehen
Wie in einer IDE, kann per Doppelklick auf Funktionen geklickt werden, um zu ihnen zu springen.
Bei der Analyse der `handle_client`-Funktion lässt sich nachvollziehen, dass zuerst `read_username` aufgerufen wird, und bei Erfolg `authenticate`.  
Eine lokale Variable (`local_4c`) mit 68 Bytes wird an beide Funktionen übergeben, was darauf hindeutet, dass hier der Username gespeichert wird.
Innerhalb der `authenticate` Funktion gibt es zwei weitere Funktionen.
Ob wir ein "Access Granted" oder "Access Denied" beommen, ist abhängig von dem `IF-Statement`.
Die Rückgabe von `get_password_input` und `generate_password` wird verglichen.


### Schwachstelle suchen (und entdecken)  
Da aus dem Input-Test bekannt ist, dass die Passwort-Eingabe ein seltsames Verhalten gezeigt hat, ist es sinnvoll die Funktion zu finden, die das Passwort handelt: `get_password_input`. 
Auch hier existiert ein lokaler Buffer von 68 Bytes (`local_4c`), jedoch liest das Programm mit `read(fd, pw_input, 0x80)` ganze 128 Bytes ein (Die Umwandlung von Hex zu Dezimal, wird durch Hovern angezeigt).
Hier liegt ein klarer **Buffer Overflow** vor: Der Stack-Buffer wird überlaufen, was bei zu langen Eingaben zur **Überschreibung der Rücksprungadresse** führt und genau diesen Effekt hatten wir im Eingabetest bereits beobachtet, als das Programm beim Passwort-Crash abstürzte.
