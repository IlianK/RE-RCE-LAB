# Reverse Engineering von Binaries mit RCE-Schwachstelle 

Im Kontext des Seminars wird in diesem Projekt die praktische Analyse einer Linux-Binary mit RCE-Schwachstelle dokumentiert. Es führt durch die typischen Schritte des Reverse Engineering: von statischer und dynamischer Analyse über Exploit-Entwicklung bis hin zur Betrachtung moderner Schutzmechanismen und deren theoretischer Umgehung.

Ziel ist es, ein fundiertes Verständnis für die Struktur von ELF-Binaries zu erlangen, den Umgang mit RE-Tools wie Ghidra und GDB zu lernen und mit `pwntools` einen einfachen Exploit für die gefundene Schwachstelle selbst zu entwickeln.

---

## Inhalte
1. [Grundlagen](docs/01_grundlagen.md)  
2. [Reverse-Engineering - Übersicht](docs/02_re_overview.md)  
3. [Statische Analyse mit Ghidra](docs/03_statische_analyse.md)
4. [Dynamische Analyse & Exploit-Development](docs/04_dynamische_analyse.md)
3. [Schutzmechanismen & Bypasses](docs/05_schutzmechanismen.md)  
5. [Weiterführende Quellen](docs/06_lernressourcen.md)  

---

## Einordnung

**Grundlagen**  
Die Grundlagen sind notwendig, um mit ELF-Binaries, den zugrundeliegenden Strukturen und Tools wie Ghidra oder GDB korrekt umzugehen und zu verstehen worauf bei einer Analyse geachtet werden sollte.

**Reverse-Engineering - Übersicht**  
Die Übersicht zeigt die Informationsquellen auf, die genutzt werden können, um Binaries zu analysieren: Von allgemeinen Informationen mit Standard-Linux Tools bis zur statischen Analyse mit Ghidra, dynamischen Analyse mit GDB und Libraries wie `pwntools` zum Exploit-Development.

**Statische Analyse mit Ghidra**:
Die Statische Analyse wird zuerst allgemein innerhalb der **Analyseübersicht** erklärt und hier spezifisch auf die Beispiel-Binary ohne aktivierten Schutzmechanismen `/examples/vuln_server/binaries/vuln_noprot` angewandt, mithilfe von Ghidra. 
Dazu wurden auch entsprechende Hilfsvideos erstellt, die die Analyse mit Ghidra zeigen unter: [`/docs/video/`](docs/videos).


**Dynamische Analyse & Exploit-Development**  
Die Binary `/examples/vuln_server/binaries/vuln_noprot` wird danach dynamisch analysiert mit GDB und schrittweise ein Exploit mithilfe der Library `pwntools` entwickelt. 

**Schutzmechanismen**  
Da das verwendete Beispiel-Binary ohne Schutzmechanismen kompiliert wurde, um den Fokus auf Analyse und Exploit-Grundlagen zu legen, werden in [`/docs/05_schutzmechanismen.md`](docs/03_schutzmechanismen.md) separat moderne Schutzmaßnahmen wie ASLR, PIE, NX, Stack Canaries und RELRO behandelt, inklusive ihrer theoretischen Umgehung.


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