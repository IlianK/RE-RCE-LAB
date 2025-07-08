# Reverse Engineering von Binaries mit RCE-Schwachstelle 

Im Rahmen des Seminars SoSe2025 dokumentiert dieses Projekt die praktische Analyse einer Linux-Binary mit einer Remote-Code-Execution-(RCE)-Schwachstelle. Dabei werden typische Schritte des Reverse Engineerings durchlaufen – von der statischen und dynamischen Analyse über die Entwicklung eines Exploits bis hin zur Betrachtung moderner Schutzmechanismen und deren möglichen Umgehungsstrategien.

Ziel des Projekts ist es, ein Verständnis für den Aufbau von ELF-Binaries zu entwickeln, den praktischen Umgang mit gängigen Reverse Engineering Tools wie Ghidra, GDB und pwntools zu erlernen und eigenständig einen einfachen Exploit für die entdeckte Schwachstelle zu erstellen.


## Projektstruktur
```bash
RE-RCE-LAB/
│
├── docs/                        
│   ├── images/                 
│   ├── videos/                  
│   ├── 01_grundlagen.md        
│   ├── 02_re_overview.md        
│   ├── 03_statische_analyse.md  
│   ├── 04_dynamische_analyse.md
│   ├── 05_schutzmechanismen.md  
│   ├── 06_lernressourcen.md     
│   └── Seminar_Slides.pdf      
│
├── examples/                   
│   ├── hex_game/                
│   └── vuln_server/           
│       ├── binaries/           
│       ├── exploits/           
│       ├── Makefile            
│       └── vuln_server.c      
│
├── .gitignore                 
├── README.md                    
└── requirements.txt             
```
---

[`/docs`](./docs/) enthält die vollständige Dokumentation dieses Projekts und ist thematisch gegliedert in:

- **Theoretische Grundlagen** – der Aufbau von ELF-Binaries, die Funktionsweise von Schutzmechanismen und ein Überblick über gängige Reverse-Engineering-Techniken.

- **Praktische Analyse** – die konkrete Untersuchung der bereitgestellten Binary mittels Tools wie Ghidra (statische Analyse) und GDB (dynamische Analyse), ergänzt durch Screenshots, Ausgaben und begleitende Erklärungen.

- **Zusätzlich enthält der Ordner**: [Videos](./docs/videos/) zur Demonstration der statischen Analyse mit Ghidra, Screenshots der dynamischen Analyse, sowie die [`Vortragsfolien`](./docs/Seminar_Slides.pdf), die im Rahmen des Seminars verwendet wurden.


[`/examples`](./examples/) enthält zwei C-basierte Beispielprojekte:
- **`hex_game`**: Ein größeres, selbst entwickeltes C-Projekt, das sich an dem interaktiven Lernspiel
[Flippy Bit and the Attack of the Hexadecimals from Base16](https://flippybitandtheattackofthehexadecimalsfrombase16.com/) orientiert.
Es wurde nicht im Rahmen des Seminars behandelt, ist aber als weiterführende Ghidra-Übung für komplexere statische Analysen vorgesehen, um tiefere Einblicke in die Ghidra-Nutzung bei größeren Codebasen zu gewinnen.

- **`vuln_server`**: Das zentrale Projektbeispiel des Seminars: ein einfacher C-basierter Server mit einer gezielt eingebauten Buffer-Overflow-Schwachstelle.
Der Ordner enthält: vorkompilierte Binaries (mit und ohne Schutzmechanismen) mithilfe des Makefile, Exploit-Skripte (mit pwntools), den vollständigen Quellcode (vuln_server.c).

---
---

## Einordnung der Doku
### [`01_grundlagen.md`](docs/01_grundlagen.md)  
Einführung in den Aufbau von ELF-Binaries, zentrale Konzepte des Reverse Engineerings. Diese Grundlagen sind wichtig, um die späteren Analyseschritte mit Ghidra und GDB zu verstehen und einzuordnen.

### [`02_re_overview.md`](docs/02_re_overview.md) 
Übersicht über mögliche Informationsquellen zur Binary-Analyse: ELF-Header, Input-Fuzzing, statische und dynamische Analyse. Einführung in Tools wie `file`, `checksec`, `readelf`, Ghidra und GDB. Ziel ist es, ein Gefühl dafür zu bekommen, wie man sich einer unbekannten Binary systematisch nähert.

### [`03_statische_analyse.md`](docs/03_statische_analyse.md) 
Statische Analyse der Binary `/examples/vuln_server/binaries/vuln_noprot` mit Ghidra. Es wird gezeigt, wie Funktionen rekonstruiert, C-Pseudocode interpretiert, relevante Strings identifiziert und potenzielle Schwachstellen erkannt werden, ohne die Binary auszuführen. Ergänzend stehen Hilfsvideos unter [`/docs/video/`](docs/videos) zur Verfügung, die die Analyse visuell begleiten.


### [`04_dynamische_analyse.md`](docs/04_dynamische_analyse.md) 
Dynamische Analyse desselben Beispiels mit GDB. Schrittweise wird ein Exploit entwickelt mithilfe von `pwntools`: erst Kontrolle über den Instruction Pointer (EIP), dann Shellcode-Injektion und schließlich das gezielte Ausführen eigenen Codes mit pwntools.

### [`05_schutzmechanismen.md`](docs/05_schutzmechanismen.md) 
Im praktischen Beispiel waren die Schutzmechanismen deaktiviert, um die Grundlagen der Exploit-Entwicklung verständlich zu vermitteln. Deshalb folgt in diesem Abschnitt eine Erklärung typischer Sicherheitsmechanismen moderner Linux-Systeme: ASLR, NX, PIE, Stack Canaries und RELRO. Beschrieben werden Funktionsweise, Erkennungsmerkmale (via checksec) und theoretische Ansätze zu ihrer Umgehung. 

### [`06_lernressourcen.md`](docs/06_lernressourcen.md) 
Zusammenstellung hilfreicher Materialien: Tutorials, CTF-Plattformen, Challenges, Tool-Dokumentationen und ergänzende Videoquellen, zur Vertiefung über das Projekt hinaus.

---
---

## Lab Setup 
Für die praktische Analyse wurde ein lokales Testlabor mit zwei virtuellen Maschinen eingerichtet: einer **Ziel-VM (Opfer)** und einer **Angreifer-VM**.

### Metasploitable VM
Die Opfer-VM basiert auf [Metasploitable 2](https://sourceforge.net/projects/metasploitable/), einer absichtlich verwundbaren Linux-Distribution für Schulungs- und Testzwecke. Sie stellt den verwundbaren Server bzw. die zu analysierende Binary bereit.


### Kali-VM
Als Angreifer-VM dient eine [Kali Linux](https://www.kali.org/get-kali/) Installation – eine auf Penetration Testing spezialisierte Distribution mit vorinstallierten RE- und Exploit-Tools. Zusätzlich wurden folgende Tools verwendet bzw. manuell installiert:
- [Ghidra](https://ghidra-sre.org/) – Reverse-Engineering-Framework, entwickelt von der NSA  
- [GDB](https://sourceware.org/gdb/) – GNU Debugger  
- [pwntools](https://docs.pwntools.com/en/stable/) – Python-Library für Exploit-Skripting  
- [pwndbg](https://github.com/pwndbg/pwndbg) – GDB-Plugin für bessere Binary-Debugging-Ansicht  
- [Visual Studio Code](https://code.visualstudio.com/) – Code Editor für Exploit-Entwicklung  

Die Ziel-Binaries wurden direkt auf der Metasploitable-VM kompiliert, um sicherzustellen, dass Architektur, Kompilerumgebung und Schutzmechanismen exakt dem Zielsystem entsprechen. Anschließend wurden sie per `scp` auf die Kali-VM übertragen, in der dann die statische und dynamische Analyse, sowie die Exploit-Entwicklung durchgeführt wurden.