## Overview

AFL++ is a modern, coverage-guided fuzzing framework designed for efficiently discovering memory safety vulnerabilities in native software. It builds on the original AFL by incorporating advanced instrumentation techniques, improved mutation strategies, and better scalability for real-world codebases. When combined with compiler-based instrumentation via clang/LLVM, AFL++ leverages compile-time or link-time analysis to insert lightweight coverage hooks directly into the target binary, allowing the fuzzer to precisely observe control-flow transitions during execution. Instrumentation modes such as LLVM, LTO, and laf-intel enable fine-grained edge coverage and improved handling of comparison-heavy code, significantly increasing path discovery and crash yield.

This repository contains **coverage-guided fuzzing exercises** using AFL++ against real world software, with the goal of reproducing known vulnerabilities and crashes.



## Targets

### Xpdf 3.02

* Fuzzed using AFL++ to trigger a crash and develop a proof-of-concept (PoC) for **CVE-2019-13288**
* See the `Xpdf/` directory for build configuration, corpus, and crash artifacts
* GitHub folder:
  [https://github.com/mooofin/AFL-exercises/tree/main/Xpdf](https://github.com/mooofin/AFL-exercises/tree/main/Xpdf)

---

### libexif 0.6.14

* Fuzzed using AFL++ to reproduce crashes corresponding to:

  * **CVE-2009-3895**
  * **CVE-2012-2836**
* Crashes are driven by malformed EXIF metadata inputs and analyzed in this folder
* GitHub folder:
  [https://github.com/mooofin/AFL-exercises/tree/main/libexif](https://github.com/mooofin/AFL-exercises/tree/main/libexif)

---

