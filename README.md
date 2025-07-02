# Reverse Engineering von Binaries mit RCE-Schwachstelle 

Im Kontext des Seminars wird in diesem Projekt die praktische Analyse einer Linux-Binary mit RCE-Schwachstelle dokumentiert. Es führt durch die typischen Schritte des Reverse Engineering: von statischer und dynamischer Analyse über Exploit-Entwicklung bis hin zur Betrachtung moderner Schutzmechanismen und deren theoretischer Umgehung.

Ziel ist es, ein fundiertes Verständnis für die Struktur von ELF-Binaries zu erlangen, den Umgang mit RE-Tools wie Ghidra und GDB zu lernen und mit `pwntools` einen einfachen Exploit für die gefundene Schwachstelle selbst zu entwickeln.


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



[`/docs`](./docs/) enthält die komplette Dokumentation der Reverse-Engineering-Analyse, unterteilt in mehrere Abschnitte. Neben der theoretischen Erklärung der ELF-Binary-Struktur, Ghidra-Nutzung, Schutzmechanismen finden sich auch [Videos](./docs/videos/) und Screenshots der Code-Ausführung, sowie die [`Vortragsfolien`](./docs/Seminar_Slides.pdf).

[`/examples`](./examples/) stellt zwei Beispielprojekte bereit:
- `hex_game` ist ein separates, größeres C-Projekt, das als Ghidra-Übung dient (nicht im Seminar behandelt).
- `vuln_server` ist das zentrale Beispiel mit einem simplen C-Server, der einen Buffer Overflow enthält. Hier finden sich kompilierte Binaries mit/ohne Schutz, zugehörige Exploits, der Quellcode und ein Makefile.


## Einordnung der Doku

### [`01_grundlagen.md`](docs/01_grundlagen.md)  
Die Grundlagen sind notwendig, um mit ELF-Binaries, den zugrundeliegenden Strukturen und Tools wie Ghidra oder GDB korrekt umzugehen und zu verstehen worauf bei einer Analyse geachtet werden sollte.

### [`02_re_overview.md`](docs/02_re_overview.md) 
Übersicht über mögliche Informationsquellen zur Binary-Analyse: ELF-Header, Input-Fuzzing, statische und dynamische Analyse. Einführung in Tools wie file, checksec, readelf, objdump, Ghidra und GDB. Ziel ist es, ein Gefühl dafür zu bekommen, wie man sich einer unbekannten Binary systematisch nähert.

### [`03_statische_analyse.md`](docs/03_statische_analyse.md) 
Praktische statische Analyse des Beispiels `/examples/vuln_server/binaries/vuln_noprot` mit Ghidra. Es wird gezeigt, wie man Funktionen erkennt, C-Pseudocode interpretiert, relevante Strings und Aufrufe identifiziert und erste Hinweise auf Schwachstellen sammelt. ohne das Programm auszuführen. Dazu wurden auch entsprechende Hilfsvideos erstellt, die die Analyse mit Ghidra zeigen unter: [`/docs/video/`](docs/videos).

### [`04_dynamische_analyse.md`](docs/04_dynamische_analyse.md)  
Hier wird die Beispiel-Binary `/examples/vuln_server/binaries/vuln_noprot` zur Laufzeit analysiert. Mit GDB wird untersucht, wie der Buffer Overflow zustande kommt. Schrittweise wird ein funktionierender Exploit entwickelt: erst Kontrolle über EIP, dann Shellcode-Injektion und schließlich das gezielte Ausführen eigenen Codes mit pwntools.

### [`05_schutzmechanismen.md`](docs/05_schutzmechanismen.md) 
Da das Beispiel-Binary bewusst ohne Schutzmechanismen kompiliert wurde, liegt der Fokus zunächst auf den Grundlagen der Analyse und Exploit-Entwicklung. In diesem Abschnitt werden anschließend gängige Sicherheitsmechanismen moderner Linux-Systeme wie ASLR, NX, PIE, Stack Canaries und RELRO erklärt,inklusive ihrer Funktionsweise, Erkennungsmerkmale (z. B. mit checksec) und möglicher theoretischer Umgehungsstrategien.

### [`06_lernressourcen.md`](docs/06_lernressourcen.md) 
Verzeichnis hilfreicher Ressourcen: Tutorials, CTF-Plattformen, Reverse Engineering Challenges, Tool-Dokumentationen und weiterführende Videos. Für alle, die sich über das Projekt hinaus vertiefen möchten.


## Lab Setup 

Für die praktische Durchführung der Analyse wurde ein lokales Testlabor mit zwei virtuellen Maschinen eingerichtet.

### Metasploitable VM
Die **Opfer-VM** basiert auf  [Metasploitable 2](https://sourceforge.net/projects/metasploitable/), einer absichtlich verwundbaren Linux-Distribution, die typischerweise zu Test- und Schulungszwecken eingesetzt wird. Sie stellt den Server bzw. die Ziel-Binary bereit. 

### Kali-VM
Als **Angreifer-VM** kommt eine [Kali Linux](https://www.kali.org/get-kali/) VM zum Einsatz. Diese Linux-Distribution ist auf Penetration-Testing spezialisiert und kommt mit zahlreichen vorinstallierten Tools. Auf der Kali-VM wurden folgende zusätzliche Tools installiert bzw. verwendet:
- [Ghidra](https://ghidra-sre.org/) – Reverse-Engineering-Tool von der NSA  
- [Visual Studio Code](https://code.visualstudio.com/) – Code Editor für Exploit-Entwicklung  
- [pwntools](https://docs.pwntools.com/en/stable/) – Python-Library für Exploit-Skripting  
- [GDB](https://sourceware.org/gdb/) – GNU Debugger  
- [pwndbg](https://github.com/pwndbg/pwndbg) – GDB-Plugin für bessere Binary-Debugging-Ansicht  


Die Ziel-Binaries wurden direkt auf der Metasploitable-VM kompiliert, um sicherzustellen, dass Architektur, Kompilierung und etwaige Schutzmechanismen dem echten Zielsystem entsprechen. Anschließend wurden sie per `scp` auf die Kali-VM übertragen, wo die statische und dynamische Analyse sowie die Exploit-Entwicklung durchgeführt wurden.