## First lets set up the enviorment 

<img width="1918" height="628" alt="image" src="https://github.com/user-attachments/assets/c6e28a26-3428-4899-9f37-63072d91ae59" />

## Lets quickly get out target which we are going to fuzz


<img width="1919" height="366" alt="image" src="https://github.com/user-attachments/assets/9282a50b-972b-438b-a561-19c873bf39e1" />


```
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```


## And lets build it :3 

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

## Installing AFL 

```bash
muffin@muffinn:~/fuzzing_xpdf/pdf_examples$ sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
```



## Building AFL 

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



 **[AFL technical details documentation](https://github.com/google/AFL/blob/master/docs/technical_details.txt)**




## One of the reasons which make AFL so fast is how it manages process execution, primarily through fork server mode and persistent mode.

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

And voila we have it ; 

<img width="1852" height="516" alt="image" src="https://github.com/user-attachments/assets/88ba1654-6902-4af3-ad6e-53d16ee422b8" />



## Now lets run AFL hooked on to the target ;

<img width="1884" height="640" alt="image" src="https://github.com/user-attachments/assets/f8fce36f-29ee-4a0f-97e5-27504d4143ea" />


Since AFL++ depends on immediate waitpid() feedback to reliably detect crashes, it refuses to run in this setup. The proper fix is to temporarily disable crash piping by running echo core | sudo tee /proc/sys/kernel/core_pattern and then rerunning afl-fuzz; this ensures crashes are reported directly and accurately. So lets do that ?



<img width="1883" height="969" alt="image" src="https://github.com/user-attachments/assets/10617b7f-3101-4d8e-95df-20b4ef48da76" />


After one hour we get some results : 3


<img width="972" height="569" alt="image" src="https://github.com/user-attachments/assets/8fd232db-5cd4-4d17-9094-d9db6d1ac08e" />


what we are interested is in what corpus input lead to the crash ? So let's check it out . 

<img width="1211" height="139" alt="image" src="https://github.com/user-attachments/assets/a11413b0-85c9-413a-9371-97f26c3e383a" />



```bash
muffin@muffinn:~/fuzzing_xpdf/out/default/crashes$ ls
README.txt  id:000000,sig:11,src:001506,time:3029564,execs:1014647,op:havoc,rep:4  id:000001,sig:11,src:000869,time:4945976,execs:1748639,op:havoc,rep:1
```


Now lets try seeing them and get into it deeply . 


Lets pick a crash file and feed it into the binary 

Great we hit a segfault 


<img width="691" height="948" alt="image" src="https://github.com/user-attachments/assets/433f2f29-5ef8-4462-9014-fa0f8ddbfc9c" />


Lets use gdb to trace it back to see what exactly is going on behind the scenes . 


We'll first rebuild this with a stack trace to see or have more symbols present in the assembly mess :(( 


```bash
rm -rf $HOME/fuzzing_xpdf/install

cd $HOME/fuzzing_xpdf/xpdf-3.02
make distclean || true

CFLAGS="-g -O0" CXXFLAGS="-g -O0" \
./configure --prefix="$HOME/fuzzing_xpdf/install"

make -j$(nproc)
make install

```


And yea 

```bash
muffin@muffinn:~/fuzzing_xpdf/xpdf-3.02$ file $HOME/fuzzing_xpdf/install/bin/pdftotext
/home/muffin/fuzzing_xpdf/install/bin/pdftotext: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c6ca250d6c2adefb20df63d3be125d96909c6424, for GNU/Linux 3.2.0, with debug_info, not stripped
```




```bash
gdb --args $HOME/fuzzing_xpdf/install/bin/pdftotext \
$HOME/fuzzing_xpdf/out/default/crashes/id:000000,sig:11,src:001506,time:3029564,execs:1014647,op:havoc,rep:4 \
$HOME/fuzzing_xpdf/output

```

<img width="1715" height="920" alt="image" src="https://github.com/user-attachments/assets/c4f2d979-1784-4ca3-89e8-b3915be20640" />


since it crashed , we'll use `bt` for the execution history of the program and see the function calls from current to wherever it started . 

```bash
#60804 0x0000555555600ec7 in Parser::getObj (this=0x5555558d9900, obj=0x7fffffef4f00, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60805 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef4f00) at XRef.cc:823
#60806 0x00005555555fbdd6 in Object::fetch (this=0x5555558d92f0, xref=0x5555556ce630, obj=0x7fffffef4f00) at Object.cc:106
#60807 0x000055555559cfe4 in Dict::lookup (this=0x5555558d96b0, key=0x55555564fa6f "Length", obj=0x7fffffef4f00) at Dict.cc:76
#60808 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef51d0, key=0x55555564fa6f "Length", obj=0x7fffffef4f00) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60809 0x0000555555601337 in Parser::makeStream (this=0x5555558d93a0, dict=0x7fffffef51d0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60810 0x0000555555600ec7 in Parser::getObj (this=0x5555558d93a0, obj=0x7fffffef51d0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60811 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef51d0) at XRef.cc:823
#60812 0x00005555555fbdd6 in Object::fetch (this=0x5555558d8d90, xref=0x5555556ce630, obj=0x7fffffef51d0) at Object.cc:106
#60813 0x000055555559cfe4 in Dict::lookup (this=0x5555558d9150, key=0x55555564fa6f "Length", obj=0x7fffffef51d0) at Dict.cc:76
#60814 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef54a0, key=0x55555564fa6f "Length", obj=0x7fffffef51d0) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60815 0x0000555555601337 in Parser::makeStream (this=0x5555558d8e40, dict=0x7fffffef54a0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60816 0x0000555555600ec7 in Parser::getObj (this=0x5555558d8e40, obj=0x7fffffef54a0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60817 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef54a0) at XRef.cc:823
#60818 0x00005555555fbdd6 in Object::fetch (this=0x5555558d8830, xref=0x5555556ce630, obj=0x7fffffef54a0) at Object.cc:106
#60819 0x000055555559cfe4 in Dict::lookup (this=0x5555558d8bf0, key=0x55555564fa6f "Length", obj=0x7fffffef54a0) at Dict.cc:76
#60820 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef5770, key=0x55555564fa6f "Length", obj=0x7fffffef54a0) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60821 0x0000555555601337 in Parser::makeStream (this=0x5555558d88e0, dict=0x7fffffef5770, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60822 0x0000555555600ec7 in Parser::getObj (this=0x5555558d88e0, obj=0x7fffffef5770, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60823 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef5770) at XRef.cc:823
#60824 0x00005555555fbdd6 in Object::fetch (this=0x5555558d82d0, xref=0x5555556ce630, obj=0x7fffffef5770) at Object.cc:106
#60825 0x000055555559cfe4 in Dict::lookup (this=0x5555558d8690, key=0x55555564fa6f "Length", obj=0x7fffffef5770) at Dict.cc:76
#60826 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef5a40, key=0x55555564fa6f "Length", obj=0x7fffffef5770) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60827 0x0000555555601337 in Parser::makeStream (this=0x5555558d8380, dict=0x7fffffef5a40, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60828 0x0000555555600ec7 in Parser::getObj (this=0x5555558d8380, obj=0x7fffffef5a40, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60829 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef5a40) at XRef.cc:823
#60830 0x00005555555fbdd6 in Object::fetch (this=0x5555558d7d70, xref=0x5555556ce630, obj=0x7fffffef5a40) at Object.cc:106
#60831 0x000055555559cfe4 in Dict::lookup (this=0x5555558d8130, key=0x55555564fa6f "Length", obj=0x7fffffef5a40) at Dict.cc:76
#60832 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef5d10, key=0x55555564fa6f "Length", obj=0x7fffffef5a40) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60833 0x0000555555601337 in Parser::makeStream (this=0x5555558d7e20, dict=0x7fffffef5d10, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60834 0x0000555555600ec7 in Parser::getObj (this=0x5555558d7e20, obj=0x7fffffef5d10, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60835 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef5d10) at XRef.cc:823
#60836 0x00005555555fbdd6 in Object::fetch (this=0x5555558d7810, xref=0x5555556ce630, obj=0x7fffffef5d10) at Object.cc:106
#60837 0x000055555559cfe4 in Dict::lookup (this=0x5555558d7bd0, key=0x55555564fa6f "Length", obj=0x7fffffef5d10) at Dict.cc:76
#60838 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef5fe0, key=0x55555564fa6f "Length", obj=0x7fffffef5d10) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60839 0x0000555555601337 in Parser::makeStream (this=0x5555558d78c0, dict=0x7fffffef5fe0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60840 0x0000555555600ec7 in Parser::getObj (this=0x5555558d78c0, obj=0x7fffffef5fe0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60841 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef5fe0) at XRef.cc:823
#60842 0x00005555555fbdd6 in Object::fetch (this=0x5555558d72b0, xref=0x5555556ce630, obj=0x7fffffef5fe0) at Object.cc:106
#60843 0x000055555559cfe4 in Dict::lookup (this=0x5555558d7670, key=0x55555564fa6f "Length", obj=0x7fffffef5fe0) at Dict.cc:76
#60844 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef62b0, key=0x55555564fa6f "Length", obj=0x7fffffef5fe0) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60845 0x0000555555601337 in Parser::makeStream (this=0x5555558d7360, dict=0x7fffffef62b0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60846 0x0000555555600ec7 in Parser::getObj (this=0x5555558d7360, obj=0x7fffffef62b0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60847 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef62b0) at XRef.cc:823
#60848 0x00005555555fbdd6 in Object::fetch (this=0x5555558d6d50, xref=0x5555556ce630, obj=0x7fffffef62b0) at Object.cc:106
#60849 0x000055555559cfe4 in Dict::lookup (this=0x5555558d7110, key=0x55555564fa6f "Length", obj=0x7fffffef62b0) at Dict.cc:76
#60850 0x00005555555fcaad in Object::dictLookup (this=0x7fffffef6580, key=0x55555564fa6f "Length", obj=0x7fffffef62b0) at /home/muffin/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#60851 0x0000555555601337 in Parser::makeStream (this=0x5555558d6e00, dict=0x7fffffef6580, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:156
#60852 0x0000555555600ec7 in Parser::getObj (this=0x5555558d6e00, obj=0x7fffffef6580, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0x0, objNum=0x4, objGen=0x0) at Parser.cc:94
#60853 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=0x4, gen=0x0, obj=0x7fffffef6580) at XRef.cc:823
```

This was a small snippet but , the important part is here that ,  this is an infinite loop, more precisely infinite recursion . 


And the repeating cycle being 
```bash 
Parser::getObj
→ Parser::makeStream
→ Object::dictLookup ("Length")
→ Dict::lookup
→ Object::fetch
→ XRef::fetch
→ Parser::getObj
```

So the parser is trying to resolve the same PDF object again and again, without any termination condition. 



This bug exists because **xpdf does not detect recursive object resolution**.
When `/Length` points back (directly or indirectly) to the same object, the parser keeps resolving forever.



You must **track visited objects** during resolution and bail out if the same object is seen again.

Conceptually:

* Keep a set of `(objNum, objGen)` currently being resolved
* Before resolving an object, check if it’s already in the set
* If yes - error out instead of recursing

### Example patch idea 

In `Parser::getObj()` or near `XRef::fetch()`:

```cpp
static std::set<std::pair<int,int>> resolving;

auto key = std::make_pair(objNum, objGen);

if (resolving.count(key)) {
    error(errSyntaxError, -1, "Recursive object reference detected");
    obj->initNull();
    return;
}

resolving.insert(key);

// existing parsing logic here

resolving.erase(key);
```

This **completely kills the infinite recursion**.


### Alternative fix: recursion depth limit (weaker but common)

Add a hard cap:

```cpp
if (++recursionDepth > 100) {
    error(errSyntaxError, -1, "Max object recursion exceeded");
    obj->initNull();
    return;
}
```

This prevents stack exhaustion but does **not fully solve logical cycles** 



 **CVE-2019-13288 Details**
[https://www.cvedetails.com/cve/CVE-2019-13288/](https://www.cvedetails.com/cve/CVE-2019-13288/)

 **AFL++ GitHub Repository**
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

 **Fuzzing Security Vulnerabilities Codelabs**
[https://fuzzing.in/codelabs/finding_security_vulnerabilities/](https://fuzzing.in/codelabs/finding_security_vulnerabilities/)

 **GDB PEDA / Pwndbg / GEF Collection**
[https://github.com/apogiatzis/gdb-peda-pwndbg-gef](https://github.com/apogiatzis/gdb-peda-pwndbg-gef)

 **GEF (GDB Enhanced Features) Official Site**
[https://hugsy.github.io/gef/](https://hugsy.github.io/gef/)









