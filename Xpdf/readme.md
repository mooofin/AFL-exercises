First lets set up the enviorment 

<img width="1918" height="628" alt="image" src="https://github.com/user-attachments/assets/c6e28a26-3428-4899-9f37-63072d91ae59" />

Lets quickly get out target which we are going to fuzz


<img width="1919" height="366" alt="image" src="https://github.com/user-attachments/assets/9282a50b-972b-438b-a561-19c873bf39e1" />


```
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```


And lets build it :3 

```
cd xpdf-3.02
sudo apt update && sudo apt install -y build-essential gcc
./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

<img width="1906" height="965" alt="image" src="https://github.com/user-attachments/assets/149a57ae-0d7c-4878-90ac-cbc7e37f35b8" />



Before starting AFL , we'll need some samples to verify so lets get them too 


<img width="1852" height="388" alt="image" src="https://github.com/user-attachments/assets/d766f69d-5ba5-4997-bd0d-0c4270f6909c" />

And voila everything is cleared up 

```bash
muffin@muffinn:~/fuzzing_xpdf/pdf_examples$ $HOME/fuzzing_xpdf/install/bin/pdfinfo -box -meta $HOME/fuzzing_xpdf/pdf_examples/helloworld.pdf
Tagged:         no
Pages:          1
Encrypted:      no
Page size:      200 x 200 pts
MediaBox:           0.00     0.00   200.00   200.00
CropBox:            0.00     0.00   200.00   200.00
BleedBox:           0.00     0.00   200.00   200.00
TrimBox:            0.00     0.00   200.00   200.00
ArtBox:             0.00     0.00   200.00   200.00
File size:      678 bytes
Optimized:      no
PDF version:    1.7
```

Installing AFL 

```bash
muffin@muffinn:~/fuzzing_xpdf/pdf_examples$ sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
```



Building AFL 

<img width="1911" height="630" alt="image" src="https://github.com/user-attachments/assets/79e297ce-8087-4a02-b233-9273a1fc2776" />

zzz

```
muffin@muffinn:~/AFLplusplus$ afl-fuzz
afl-fuzz++4.35c based on afl by Michal Zalewski and a large online community

afl-fuzz [ options ] -- /path/to/fuzzed_app [ ... ]

Required parameters:
  -i dir        - input directory with test cases (or '-' to resume, also see
                  AFL_AUTORESUME)
  -o dir        - output directory for fuzzer findings

Execution control settings:
  -P strategy   - set fix mutation strategy: explore (focus on new coverage),
                  exploit (focus on triggering crashes). You can also set a
                  number of seconds after without any finds it switches to
                  exploit mode, and back on new coverage (default: 1000)
  -p schedule   - power schedules compute a seed's performance score:
                  explore(default), fast, exploit, seek, rare, mmopt, coe, lin
                  quad -- see docs/FAQ.md for more information
  -f file       - location read by the fuzzed program (default: stdin or @@)
  -t msec       - timeout for each run (auto-scaled, default 1000 ms). Add a '+'
                  to auto-calculate the timeout, the value being the maximum.
  -m megs       - memory limit for child process (0 MB, 0 = no limit [default])
  -O            - use binary-only instrumentation (FRIDA mode)
  -Q            - use binary-only instrumentation (QEMU mode)
  -U            - use unicorn-based instrumentation (Unicorn mode)
  -W            - use qemu-based instrumentation with Wine (Wine mode)
  -X            - use VM fuzzing (NYX mode - standalone mode)
  -Y            - use VM fuzzing (NYX mode - multiple instances mode)
  -K dir        - use python script to interact with GUI (GUI mode)
```

AFL++ is a coverage-guided fuzzer that repeatedly runs a target program with mutated inputs and watches which code paths get executed. It instruments the program to track basic-block or edge coverage, keeps inputs that discover new paths, and mutates those “interesting” inputs more aggressively. Over time, this feedback loop lets AFL++ explore deeper logic, automatically surfacing crashes, hangs, and weird edge cases without knowing anything about the program’s internals.



Now for fuzzing we need to build the application with afl-clang-fast , so that it adds the nessecary things needed for AFL , below are some examples . 

<img width="752" height="1073" alt="image" src="https://github.com/user-attachments/assets/3cb14628-ad49-4224-8101-014124ef787e" />


https://github.com/google/AFL/blob/master/docs/technical_details.txt 

One of the reasons which make AFL so fast is how it manages process execution, primarily through fork server mode and persistent mode.

<img width="2900" height="1400" alt="image" src="https://github.com/user-attachments/assets/a9ec6ab3-36b4-445c-a13f-c902eb99c9ce" />


### Fork Server Mode

Fork server mode is the default execution model in AFL-style fuzzers.

When the instrumented program starts, AFL++ runs it once and stops execution at `main()`. From this point onward, instead of repeatedly launching the program from scratch using `execve`, AFL++ uses `fork()` to create lightweight child processes. Each child:

* Receives a mutated input
* Executes the target logic once
* Exits immediately after processing

Because program initialization happens only once, this avoids repeated startup costs and delivers a massive speedup compared to naive fuzzing. However, each iteration still involves a fork and process teardown, which can become expensive for very tight fuzz loops or heavy parsers.



### Persistent Mode

Persistent mode pushes performance even further by minimizing process creation entirely.

In persistent mode, the target program stays alive and processes **multiple fuzz inputs within a single process instance**. Instead of forking for every test case, AFL++ repeatedly feeds new inputs into a loop inside the program. This is especially effective when:

* Initialization is expensive
* The target logic can be cleanly re-entered
* State can be reset between iterations



### Writing a Persistent Mode Harness

To enable persistent mode, you typically write a small harness that reads input and processes it inside an `__AFL_LOOP()`.

```c
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define MAX_INPUT 1024

void process_input(const uint8_t *data, size_t size) {
    if (size > 4 && memcmp(data, "muffin!", 4) == 0) {
        char buf[8];
        memcpy(buf, data, size); // intentional bug erm 
    }
}

int main(void) {
    uint8_t buf[MAX_INPUT];

    while (__AFL_LOOP(1000)) {
        ssize_t len = read(0, buf, sizeof(buf));
        if (len <= 0) break;

        process_input(buf, len);
    }

    return 0;
}
```

Here, `__AFL_LOOP()` tells AFL++ to repeatedly execute the target logic without restarting the process. The argument controls how many iterations occur before AFL++ allows a restart to mitigate memory leaks or corrupted state.



## Back on track lets build with afl's clang 

```bash
export LLVM_CONFIG="llvm-config-11"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```




















