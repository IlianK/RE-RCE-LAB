
# Grundlagen

## Inhalte
1. [Was ist Remote Code Execution (RCE)?](#rce)
   - [Injection](#injection)
   - [Deserialization](#deserialization)
   - [Memory Corruption](#memory_corruption)
   - [Übersicht und Gemeinsamkeiten](#overview_common)

2. [RCE-Schwachstellen in Binaries](#rce-schwachstellen-in-binaries)

3. [Was ist Reverse Engineering (RE)?](#was-ist-reverse-engineering-re)
   - [Schwierigkeit von RE](#schwierigkeit-von-re)
   - [Motivation hinter RE](#motivation-hinter-re)

4. [Source <-> Binary](#source2bin)
   - [Compilation – vom Quellcode zum Assembler](#compilation)
   - [Assembly & Linking – von Assembler zu Binärdatei](#assembly)
   - [Disassembly – zurück zu Assembler](#disassembly)
   - [Decompilation – zurück zu C-ähnlichem Code](#decompilation)

5. [Linux ELF-Binaries – Aufbau & Analyse](#linuxelf)
   - [ELF Header](#elfheader)
   - [Sections – logische Struktur](#sections)
   - [Program Header Table (Segmente) – für die Ausführung](#segments)
   - [Symboltabellen & Stripped Binaries](#stripped)

6. [Referenzen](#references)


<a id="rce"></a>
## Was ist Remote Code Execution (RCE)?
Remote Code Execution (RCE) bezeichnet eine schwerwiegende Sicherheitslücke, bei der ein Angreifer über ein Netzwerk (z. B. über das Internet oder LAN) beliebigen Code auf einem Zielsystem ausführen kann, ohne physischen Zugriff oder Interaktion mit einem legitimen Nutzer. Damit gehört RCE zu den kritischsten Schwachstellen überhaupt und ermöglicht beispielsweise das Deployment von Malware, Datenexfiltration oder eine vollständige Systemübernahme <a id="cite8"></a>[<a href="#ref8">8</a>].

Innerhalb der größeren Klasse Arbitrary Code Execution (ACE) ist RCE die Variante, die remote ausgeführt wird. ACE umfasst dagegen auch lokale Codeausführung auf Systemen, die ein Angreifer bereits kompromittiert hat
<a id="cite8"></a>[<a href="#ref8">8</a>].

Die meisten Quellen reden von drei typischen Angriffstypen:

---

<a id="injection"></a>
### Injection:
Injection-Angriffe entstehen, wenn ein Angreifer ungeprüfte Eingaben direkt in einen Befehl einfügen kann, der dann vom System (z. B. SQL-Interpreter, Shell) ausgeführt wird.
Am bekanntesten ist SQL-Injection, aber es existieren auch OS Command-, LDAP-, oder XML-Injections <a id="cite11"></a>[<a href="#ref11">11</a>].

Ein Webformular fragt den Benutzernamen ab:

```sql
SELECT * FROM users WHERE username = '$input';
```

Angreifer gibt ein:
```sql
' OR '1'='1
```

Wodurch der Befehl wird zu:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1';
```

Damit werden alle Benutzer zurückgegeben, ohne Login oder Passwortprüfung.


---

<a id="deserialization"></a>
### Deserialization:
Deserialization‑Angriffe entstehen, wenn eine Anwendung unsichere, serialisierte Daten (z. B. Base64-Strings oder Java-Objekte) ohne ausreichende Validierung in Runtime‑Objekte umwandelt. Angreifer können dabei manipulierte Objekte einschleusen, die beim Deserialisieren automatisch bestimmte Methoden ausführen – häufig über sogenannte Gadget Chains, bestehend aus seriellen Objekten bestehender Klassenbibliotheken (z. B. Apache Commons Collections, Spring) <a id="cite9"></a>[<a href="#ref9">9</a>].

Wichtig: Dabei wird kein neuer Code eingeschleust – stattdessen nutzt der Angriff reflectiv vorhandene Methoden wie `Runtime.getRuntime().exec()` über eine definiert strukturierte Kette (Gadget Chain). Solche Chains werden typischerweise von Tools wie ysoserial generiert und basieren darauf, dass gängige Libraries (z. B. `InvokerTransformer` in Commons Collections) zur Laufzeit Code ausführen können <a id="cite9"></a>[<a href="#ref9">9</a>].

Zum Beispiel wurde das CommonsCollections1‑Gadget Chain eingehend analysiert: Hier wird beim Deserialisieren über `AnnotationInvocationHandler`, `Proxy`, `LazyMap` über `ChainedTransformer` letztlich `Runtime.exec()`aufgerufen, alles über vorhandene Klassen im Classpath <a id="cite9"></a>[<a href="#ref9">9</a>].

---

<a id="memory_corruption"></a>
### Memory Corruption:
Memory Corruption beschreibt das Überschreiben von Speicherbereichen, was in niedrigsprachigen Programmen (z. B. C/C++) leicht passieren kann.
Klassische Beispiele sind unsauber verwaltete Speicherbereiche, wie Buffer Overflows oder Out-of-Bounds-Zugriffe, bei denen wichtige Kontrollstrukturen wie Rücksprungadressen überschrieben werden können <a id="cite8"></a>[<a href="#ref8">8</a>].

```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input); 
}
```
Wenn mehr als 64 Bytes in `buffer` kopiert werden, überschreibt das angrenzenden Speicher, inklusive des Rücksprungzeigers (EIP/RIP). Dadurch kann ein Angreifer über eine geeignete Payload Shellcode einschleusen und den Kontrollfluss des Programms übernehmen, sofern keine Schutzmechanismen (z. B. Stack Canaries, NX) aktiviert sind <a id="cite12"></a>[<a href="#ref12">12</a>].

Buffer Overflow ist eine der bekanntesten Formen der Memory Corruption, bei der angrenzender Speicher, etwa Rücksprungadressen oder Funktionszeiger, überschrieben wird, was in der Exploit-Entwicklung zur Kontrolle des Programmflusses genutzt wird (z. B. via Return-Oriented Programming, ROP) <a id="cite12"></a>[<a href="#ref12">12</a>].

Memory Corruption umfasst aber auch andere Fehlerklassen wie Use‑after‑Free, heap‑basierte Overflows und integer overflow/bounds errors, die ähnliche Folgen haben können <a id="cite12"></a>[<a href="#ref12">12</a>].

---
---

<a id="overview_common"></a>
### Übersicht und Gemeinsamkeiten:

#### Übersicht:

| **Angriffstyp**       | **Schwachstellen / Vorgehen**                                                 | **Schutzmaßnahmen**                                              |
| --------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| **Injection**         | Ungefilterte Eingaben führen zur direkten Einbindung in Befehle / SQL-Queries | Input-Validierung, Prepared Statements, Whitelist                |
| **Deserialization**   | Manipulierte Objekte lösen Hooks aus oder aktivieren native Methoden          | Safe-Deserialization-Libraries, Whitelist-Strategien             |
| **Memory Corruption** | Buffer Overflow, Out-of-Bounds-Writes überschreiben Speicher/ Rücksprungadressen        | Sichere APIs, Compiler-Schutzmechanismen (Canary, NX, ASLR, PIE) |


#### Gemeinsamkeiten:
Trotz technischer Unterschiede folgen Injection, Deserialization und Memory Corruption denselben grundlegenden Mustern:

| **Schritt**                                     | **Injection**                                              | **Deserialization**                                   | **Memory Corruption**                                                |
| ----------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------- |
| **1. Einschleusen externer Daten**              | Formulare, URL-Parameter                                   | Serialisierte Objekte (JSON, XML, binär)              | Eingaben über `argv`, Netzwerkpakete, benutzerdefinierte Puffer      |
| **2. Fehlende Prüfung**                         | Keine Input-Sanitization, falsches Escaping                | Keine Typfilter, keine Validierung vor `readObject()` | Keine Grenzprüfung (`strcpy`, `memcpy`, Integer-Überläufe)           |
| **3. Kritische Verarbeitung**                   | SQL- oder Shell-Interpreter verarbeitet Eingabe als Befehl | Deserializer instanziiert Objekte automatisch         | Speicheroperation beeinflusst Rücksprungadresse / Kontrollstrukturen |
| **4. Kontrollfluss-Manipulation**               | Logikverzweigung durch manipulierte Ausdrücke              | Methodenausführung über Gadget Chain (z. B. `exec()`) | Kontrolle über Rücksprungadresse / Funktionspointer                  |
| **5. Zweckentfremdung vorhandener Komponenten** | Nutzung von `system()`, Shell, Bash                        | Java-Bibliotheken, Reflection, CommonsCollections     | Vorhandene Instruktionen (z. B. ROP-Gadgets, libc-Funktionen)        |



---
---


## RCE-Schwachstellen in Binaries
RCE-Schwachstellen können im Quellcode erkennbar sein, zumindest für Entwickler mit Einblick in die Codebasis.
Doch wenn der Quellcode nicht verfügbar ist, wie es bei proprietärer Software oder fremden Binärdateien der Fall ist, bleibt nur die Analyse des kompilierten Binaries.

Diese Schwachstellen sind jedoch im kompiliertem Code nicht mehr unmittelbar sichtbar, da sie durch Optimierung, Obfuskation und den Verlust von Symbolinformationen (z. B. Funktionsnamen, Variablennamen) verdeckt werden.
Sie lassen sich von außen manchmal anhand auffälliger Eingabemuster oder Programmverhalten vermuten, wie durch:
- unerwartete Abstürze,
- Speicherzugriffsfehler,
- auffällige Reaktion auf bestimmte Eingaben

Doch diese Hinweise können nicht eindeutig oder gar nicht vorhanden sein. In solchen Fällen kann **Reverse Engineering (RE)** helfen, Einblicke in das Verhalten der Software auf Binärebene zu bekommen. Da Binaries das Ergebnis der Kompilation des Quellcodes sind, sind die RCE-Schwachstellen, die wir im Binary analysieren können, genau die Programmierfehler aus dem Quellcode, nur versteckt hinter Assemblersyntax.


---
---


## Was ist Reverse Engineering (RE)?
Reverse Engineering (RE) bezeichnet den Prozess der Rückführung einer Software (oder auch Hardware) in eine verständliche Darstellung ihrer inneren Struktur und Funktion, ohne Zugang zum ursprünglichen Quellcode oder zur technischen Dokumentation.

Im Kontext von Software bedeutet das:
Ausgehend von einer kompilierten Datei (also Maschinencode oder Bytecode) wird versucht, die Logik der Anwendung nachträglich zu rekonstruieren. Ziel ist es, die Funktion, den Ablauf und die Datenverarbeitung der Software zu verstehen <a id="cite1"></a>[<a href="#ref1">1</a>].

Das IEEE definierte Reverse Engineering schon 1990 als „das Analysieren eines Zielsystems, um dessen Komponenten und deren Beziehungen zu identifizieren und das System in einer anderen Form oder auf höherer Abstraktionsebene darzustellen“ <a id="cite1"></a>[<a href="#ref1">1</a>].

RE versucht Instruktionen aus dem Binärcode zu extrahieren (Disassembly), diese in eine höhere, verständliche Repräsentation zu überführen (Decompilation) und daraus das ursprüngliche Verhalten der Software abzuleitenm wie Funktionsweise, Ein-/Ausgaben, Sicherheitslücken oder Kommunikationswege.

---


### Schwierigkeit von RE
Compiler abstrahieren und optimieren den ursprünglichen Quellcode, wodurch viele lesbare Strukturen (z. B. Variablennamen, Kommentare, Formatierungen) verloren gehen.

Das Resultat ist stark verdichteter Maschinencode, der schwer lesbar und analysierbar ist.
Hinzu kommt: Maschinencode ist plattform- und architekturabhängig. 

Intel x86 (32-bit), x86_64 (64-bit), ARM oder Apple M1 (ARM64), haben ein jeweils unterschiedliches Instruction Set, welches exakt defineirt, welche Binärcodes für welche Operationen stehen (z. B. „Addiere zwei Register“) und wie Speicherzugriffe, Registerverwendung und Systemaufrufe funktionieren.
Dadurch hat jede Architektur ihre eigene Instruction Set Architecture (ISA), also ihr eigenes Assembler-Sprachformat.

Beispielsweise: Ein einfacher Maschinenbefehl für x86 wie `mov eax, 1` (Register eax bekommt den Wert 1) ist in ARM `mov r0, #1`. Auch die Register-Namen, Byte-Reihenfolge (Endianness) und Calling Conventions sind unterschiedlich. 

RE muss diese Unterschiede beispielsweise beim Nachvollziehen von Funktionsaufrufen oder Stack-Layouts berücksichtigen.
Auch Exploit-Entwicklung ist direkt betroffen: So funktionieren z. B. Return-Oriented Programming (ROP) oder Buffer Overflows sehr unterschiedlich auf x86 vs. ARM, da die Rücksprung-Mechanismen und Sicherheitsfeatures abweichen <a id="cite4"></a>[<a href="#ref4">4</a>].



---
---

## Motivation hinter RE
RE wird aus verschiedenen Gründen betrieben:

![motivators](images/theory/motivators.png)

### Softwareanalyse / Sicherheitssforschung
In der IT-Security wird RE eingesetzt, um Schwachstellen in fremder Software aufzudecken (Security Auditing) oder Schadsoftware zu analysieren, wie beispielsweise die Ransomware WannaCry. <a id="cite3"></a>[<a href="#ref3">3</a>]. Dabei geht es oft darum, das Verhalten eines Programms ohne Quellcode zu verstehen zur Exploit-Prävention oder Erkennung von Command-and-Control-Mechanismen. Die gleichen Techniken werden allerdings auch von Angreifern genutzt, um Sicherheitslücken zu entdecken und für Exploits und Remote Code Execution (RCEs) auszunutzen.

### Spielentwicklung und Modding
In der Gaming-Community wurde und wird RE aktiv genutzt, um Spielmechaniken, Datenstrukturen und Netwerkprotokolle eines Spiels zu verstehen. Einerseits ermöglicht das Fans und Entwicklern, Mods oder eigenge Tools zu erstellen und so Spiele zu erweitern, Fehler zu beheben oder auf anderen Plattformen lauffähig zu machen, andererseits wurde RE auch zur Entwicklung von Cheats bzw. zur Umgehung von Anti-Cheat-Systemen verwendet <a id="cite2"></a>[<a href="#ref2">2</a>].

### Digital Rights Management (DMR)
Auch in der Umgehung von Kopierschutz spielt RE eine Rolle. Das Digital Rights Management bezeichnet technische Schutzmaßnahmen, die eingesetzt werden, um digitale Inhalte wie Software, Filme oder Musik  vor unbefugtem Zugriff, Kopieren oder Weiterverbreitung zu schützen. Durch RE können die Schutzmechanismen nachvollzogen werden. In vielen Ländern, bewegen sich solche Analysen rechtlich zwischen „Fair Use“ und Urheberrechtsverletzung. Obwohl RE von DRM-Technologien in bestimmten Fällen (z. B. für Interoperabilität oder Forschung) legal sein kann, gelten sie oft als Verstoß gegen Gesetze wie den [DMCA (Digital Millennium Copyright Act)](https://www.copyright.gov/dmca/) oder die [EU-Urheberrechtsrichtlinie](https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:32019L0790). Denn mit dem Wissen kann auch der Kopierschutz entfernt werden. Dieser Vorgang ist als „Cracking“ bekannt <a id="cite4"></a>[<a href="#ref4">4</a>, S. 7]. 

### Wartung und Re-Dokumentation
Bei Legacy-Systmen ohne aktuelle Dokumentation kann RE helfen, die Funktionsweise nachträglich zu rekonstruieren und neu zu dokumentieren. Wenn Originalteile für ältere Hardware nicht mehr verfügbar sind / nicht mehr produziert werden, können die Teile (z.B. Chips) analysiert werden, um Altsysteme weiterhin betreiben und warten zu können. <a id="cite1"></a>[<a href="#ref1">1</a>, P.15].

### Wettbewerbsanalyse und technische Spionage
Unternehmen und staatliche Akteuere können RE auch nutzen, um Funktion, Design, ggf. auch Materialien von Konkurrenz-Produkten und Technologien zu analysieren, und durch das gewonnene Wissen, diese nachzubauen, selbst eigene Entiwcklungen voranzutreiben oder zu verbessern. <a id="cite1"></a>[<a href="#ref1">1</a>, P.13].

### Neugier und Lernzwecke
Nicht zuletzt ist Neugier ein großer Treiber: Viele Forscher, Hacker oder einfach Technik-Interessierte betreiben RE, um Verständnis für Systeme und Hardware-Sprache zu entwickeln. Besonders im Bereich Security Research und Capture-the-Flag (CTF) ist das ein anerkannter und wertvoller Zugang zur Technologie.


---
---

<a id="source2bin"></a>
## Source <-> Binary
Bevor man sich mit RE beschäftigt, lohnt sich ein kurzer Rückblick auf den regulären Build Prozess: Der Weg vom Quellcode zur ausführbaren Binärdatei.

Ein Binary ist ein ausführbares Programm, das vollständig in Maschinencode vorliegt und von einer bestimmten Prozessorarchitektur interpretiert werden können. Binaries entstehen durch die Übersetzung von Quellcode mittels Compiler und Linker und enthalten neben ausführbarem Code auch strukturierte Metadaten, die das Betriebssystem benötigt, um das Programm korrekt in den Speicher zu laden und auszuführen.


---

<a id="compilation"></a>
### Compilation - vom Quellcode zum Assembler
Der Prozess beginnt mit dem C-Preprozessor, der alle Präprozessor-Direktiven im Quellcode verarbeitet:`#include`, `#define` oder bedingte Kompilierungsanweisungen wie `#ifdef`. Dabei werden Header-Dateien in den Code eingebunden. Das Ergebnis ist ein erweiterter Quelltext, der keine Präprozessor-Befehle mehr enthält, sondern reinen, kompilierbaren C-Code <a id="cite6"></a>[<a href="#ref6">6</a>].

Der so vorbereitete Quelltext wird dann vom C/C++-Compiler **architekturspezifischen Assembler-Code** übersetzt. Dabei wandelt der Compiler jede C-Anweisung in eine äquivalente Folge maschinennaher Instruktionen um. In dieser Phase kommen auch Optimierungen zum Einsatz, wie die Entfernung ungenutzter Funktionen, die Umordnung von Befehlen oder die Inlining kleiner Funktionen, um effizienteren und kompakteren Code zu erzeugen. Für jedes `.c`-File ensteht dabei eine separate Assembler-Repräsentation, die aber noch nicht ausführbar ist <a id="cite6"></a>[<a href="#ref6">6</a>].


![compilation](images/theory/compilation.png)


<a id="assembly"></a>
### Assembly & Linking - von Assembler zu Binärdatei
Nach der Übersetzung durch den Compiler folgt die Assemblierung in Objektdateien (.o): Der Assemblierer wandelt den fertigen Assembler-Code in Maschinencode um. Diese Objektdateien enthalten nicht nur den Code, sondern auch symbolische Referenzen (z. B. Funktions- oder Variablennamen) und Relocation-Informationen, die dem Linker später mitteilen, wo Adressen im Code nachträglich angepasst werden müssen  <a id="cite13"></a>[<a href="#ref13">13</a>].

In der letzten Phase übernimmt der **Linker** die Aufgabe, alle Objektdateien (file-1.o, file-2.o usw.) zu einem vollständigen, ausführbaren Programm zu verbinden. Zusätzlich werden externe statische Bibliotheken eingebunden, z.B. die Funktionen wie `printf()` oder `malloc()` enthalten können. Der Linker löst symbolische Referenzen auf und stellt sicher, dass alle Funktionsaufrufe auf die korrekten Speicheradressen zeigen.

Dabei wird zwischen **statischem** und **dynamischem** Linking unterschieden. Dynamische Bibliotheken werden erst zur Laufzeit eingebunden z. B. durch **PLT (Procedure Linkage Table)** und **GOT (Global Offset Table)** <a id="cite5"></a>[<a href="#ref5">5</a>].

Das Ergebnis ist eine vollständige, ausführbare Binärdatei (z. B. `a.out`, ELF-Format).

![assembly_disassembly](images/theory/assembly_disassembly.png)

<a id="disassembly"></a>
### Disassembly – zurück zu Assembler
Beim **Reverse Engineering** möchte man den Prozess umkehren. Ein **Disassembler** analysiert den Maschinencode und erzeugt pro Architektur das passende **Assembler-Listing** (z. B. für x86, ARM, MIPS).

Da Maschinencode lediglich eine Abfolge von Bytes ist, ist ein korrektes Verständnis der **Architektur (ISA)** notwendig. Tools wie `objdump` oder Ghidra erkennen Befehlsketten und erzeugen lesbare Befehlskürzel (Assembler-Mnemonics).

Allerdings fehlen viele Informationen, wie Variablennamen, Datentypen oder Kommentare, wenn diese beim Kompilieren entfernt wurden.

Wenn Debug-Informationen vorhanden sind (z. B. durch -g beim Kompilieren), enthalten Object Files und Binaries zusätzliche Symbole, was Disassemblern und Debuggern erheblich hilft. Wird jedoch „stripping“ durchgeführt, verschwinden diese Informationen.


---

<a id="decompilation"></a>
### Decompilation - zurück zu C-ähnlichem Code
Decompiler gehen noch einen Schritt weiter: Sie versuchen, aus dem Maschinencode einen lesbaren, C-ähnlichen Pseudocode zu rekonstruieren.

Dazu wird der Code zunächst in eine Intermediate Representation (IR) überführt: eine plattformunabhängige Zwischensprache. Ghidra verwendet beispielsweise die Zwischensprache P-Code <a id="cite7"></a>[<a href="#ref7">7</a>]. Aus dieser IR werden dann:

- Kontrollstrukturen (if, while, switch),
- lokale Variablen,
- Funktionsgrenzen und Rückgabewerte

rekonstruiert und in einer höheren Sprache dargestellt. Obwohl die ursprünglichen Namen und Kommentare fehlen, lässt sich das Programmverhalten gut nachvollziehen.


![decompilation](images/theory/decompilation.png)


---
---

<a id="linuxelf"></a>
## Linux ELF-Binaries – Aufbau & Analyse

Unter Linux werden ausführbare Programme typischerweise im **ELF-Format (Executable and Linkable Format)** gespeichert. Dieses Format organisiert die verschiedenen Bestandteile eines Programms sowohl für die **Analyse** als auch für die **Ausführung durch das Betriebssystem**. Eine ELF-Datei besteht aus mehreren Hauptbestandteilen <a id="cite5"></a>[<a href="#ref5">5</a>]:
| Bereich         | Zweck                                | Beispiel / Inhalt                          |
|----------------|---------------------------------------|--------------------------------------------|
| ELF Header      | Basisinfos zur Datei                 | Architektur, Entry Point, Offsets          |
| Sections        | Logische Programmstruktur            | `.text`, `.rodata`, `.data`, `.symtab`     |
| Segmente (PHT)  | Laufzeit-Speicheraufteilung          | RWX-Rechte, Laden durch Betriebssystem     |
| Symboltabelle   | Analyse- und Debugginghilfe          | Funktionsnamen, Variablennamen             |


![elf_binary](images/theory/elf_binary.png)


---

<a id="elfheader"></a>
### ELF Header
Der **ELF Header** steht am Anfang jeder ELF-Datei und enthält Metadaten zur Datei selbst <a id="cite5"></a>[<a href="#ref5">5</a>]<a id="cite6"></a>[<a href="#ref6">6</a>]:
- **Magic Number**: Erste 4 Bytes (0x7F 45 4C 46, also `0x7F ELF`) identifizieren die Datei eindeutig als ELF.
- **Architektur**: 32 oder 64 Bit (`e_class`)
- **Plattform**: z. B. Intel x86, ARM (`e_machine`)
- **Offsets**: Zeiger auf die Program Header Table (PHT) und Section Header Table (SHT)
- **Entry Point**: Startadresse des Programmcodes (z. B. `_start`)


---

<a id="sections"></a>
### Sektionen – für die logische Struktur
Sections sind logische Abschnitte, die vom Compiler und Linker genutzt werden. Sie **dienen der Analyse, nicht der Ausführung** und werden beim Programmstart nicht direkt geladen. Eine **Section gehört immer zu einem Segment**. Verwaltet werden alle Sections im sogenannten Section Header Table (SHT). Der SHT ist eine Art Inhaltsverzeichnis für alle Sections der ELF-Datei. Jede Section hat dort einen Eintrag mit Metainformationen wie Name, Typ, Offset, Größe und Zugriffsrechten. Tools wie readelf, objdump oder Decompiler (z. B. Ghidra) greifen auf den SHT zu, um die Struktur und Symbolik der Binary zu analysieren <a id="cite6"></a>[<a href="#ref6">6</a>].

| Section      | Inhalt / Zweck                              | Zugriffsrechte      |
|--------------|----------------------------------------------|---------------------|
| `.text`      | Auszuführbarer Code                          | RX (Read, Execute)  |
| `.rodata`    | Konstanten, z. B. Format-Strings              | R (Read-Only)       |
| `.data`      | Initialisierte globale / statische Daten     | RW (Read, Write)    |
| `.bss`       | Nicht initialisierte Daten (nur reserviert)  | RW (Read, Write)    |
| `.symtab`    | Symboltabelle mit Funktions-/Variablennamen  | -                   |
| `.strtab`    | Zeichenketten für Symbole                    | -                   |



---

<a id="segments"></a>
### Segmente – für die Ausführung
Im Gegensatz zu Sections sind **Segmente** für die **tatsächliche Ausführung** relevant. Sie werden beim Programmstart vom Betriebssystem in den RAM geladen. Segmente werden in der **Program Header Table (PHT)** definiert und enthalten die Speicherbereiche, die tatsächlich zur Laufzeit in den RAM geladen werden mit dazugehörigen **Zugriffsrechte** (R/W/X) <a id="cite5"></a>[<a href="#ref5">5</a>]<a id="cite6"></a>[<a href="#ref6">6</a>]. 
Ein Segment kann **mehrere Sections enthalten** oder auch **keine zugeordnete Section** haben (z. B. bei reservierten Stack-Segmenten)


| Segmenttyp       | Inhalt                                  | Speicherrechte |
|------------------|------------------------------------------|----------------|
| `LOAD`           | Hauptspeicherbereiche (Code, Daten)      | RX, RW         |
| `GNU_STACK`      | Stack-Segment                            | RW oder RWX    |
| `INTERP`         | Interpreter (z. B. Pfad zur libc.so)      | -              |


---

<a id="stripped"></a>
### Symboltabellen & Stripped Binaries
ELF-Dateien können zusätzliche Debug-/Analyseinformationen enthalten wie:

- `.symtab` – Symbolnamen für Funktionen und Variablen
- `.strtab` – dazugehörige Zeichenketten
- `.debug*` – ggf. weitere Debug-Infos

Diese sind **nicht erforderlich für die Ausführung**.
Werden sie entfernt (z. B. via `strip`), spricht man von einer **stripped Binary**. In solchen Fällen verwenden Analyse-Tools generische Namen wie `FUN_00123abc` <a id="cite6"></a>[<a href="#ref6">6</a>].


---
---

[Nächstes Kapitel: RE-Overview](/docs/02_re_overview.md)

---
---

<a id="references"></a>
## Referenzen

[↩](#cite1) <a id="ref1">[1]</a> E. J. Chikofsky and J. H. Cross, "Reverse engineering and design recovery: a taxonomy," *IEEE Software*, vol. 7, no. 1, pp. 13–17, Jan. 1990. [doi:10.1109/52.43044](https://ieeexplore.ieee.org/document/43044)

[↩](#cite2) <a id="ref2">[2]</a> W. Scacchi, "Modding as an Open Source Approach to Extending Computer Game Systems," in *Open Source Systems: Grounding Research*, S.A. Hissam, B. Russo, M.G. de Mendonça Neto, and F. Kon, Eds., IFIP Advances in Information and Communication Technology, vol. 365, Springer, Berlin, Heidelberg, 2011. [https://doi.org/10.1007/978-3-642-24418-6_5](https://doi.org/10.1007/978-3-642-24418-6_5)

[↩](#cite3) <a id="ref3">[3]</a> W. Alraddadi and H. Sarvotham, "A comprehensive analysis of WannaCry: technical analysis, reverse engineering, and motivation," *International Journal of Computer Applications*, vol. 182, no. 45, pp. 1–8, 2018, [https://people-ece.vse.gmu.edu/coursewebpages/ECE/ECE646/F19/project/F18_presentations/Session_III/Session_III_Report_3.pdf]

[↩](#cite4) <a id="ref4">[4]</a> E. Eilam, *Reversing: Secrets of Reverse Engineering*, John Wiley & Sons, 2011, [https://media.wiley.com/product_data/excerpt/17/07645748/0764574817-20.pdf]

[↩](#cite5) <a id="ref5">[5]</a> Linux Audit, "ELF Binaries on Linux: Understanding and Analysis," [https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/), accessed May 28, 2025.

[↩](#cite6) <a id="ref6">[6]</a>Github, x0nu11byt3/elf_format_cheatsheet.md, https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779

[↩](#cite7) <a id="ref7">[7]</a> Ghidra P-Code: https://riverloopsecurity.com/blog/2019/05/pcode/#:~:text=P,that%20work%20with%20assembly%20code

[↩](#cite8) <a id="ref8">[8]</a> Remote Code Execution - RCE: https://www.rapid7.com/fundamentals/what-is-remote-code-execution-rce/

[↩](#cite9) <a id="ref9">[9]</a> An In-depth Study of Java Deserialization Remote-Code Execution
Exploits and Vulnerabilities: https://bodden.de/pubs/sbbl22deserial.pdf

[↩](#cite10) <a id="ref10">[10]</a> Cloudfare - RCE Overview: https://www.cloudflare.com/learning/security/what-is-remote-code-execution/

[↩](#cite11) <a id="ref11">[11]</a> Injection Overview: https://www.indusface.com/learning/injection-attacks/

[↩](#cite12) <a id="ref12">[12]</a> Understanding Memory Safety Vulnerabilities: Top Memory Bugs and How to Address Them: https://runsafesecurity.com/blog/memory-safety-vulnerabilities/

[↩](#cite13) <a id="ref13">[13]</a> Symbol Resolution & relocation: https://duetorun.com/blog/20230627/symbol-resolution-relocation/