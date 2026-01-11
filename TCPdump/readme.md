
### Getting the Target Ready

Lets start by setting up a clean workspace for fuzzing tcpdump.

```bash
cd $HOME
mkdir fuzzing_tcpdump && cd fuzzing_tcpdump/
```

Lets then fetch and extract the tcpdump source code.

```bash
wget https://github.com/the-tcpdump-group/tcpdump/archive/refs/tags/tcpdump-4.9.2.tar.gz
tar -xzvf tcpdump-4.9.2.tar.gz
```

tcpdump depends on libpcap for packet parsing, so lets grab that next.

```bash
wget https://www.tcpdump.org/release/libpcap-1.8.0.tar.gz
tar -xzvf libpcap-1.8.0.tar.gz
```

Lets then configure and build libpcap with shared libraries disabled.

```bash
cd $HOME/fuzzing_tcpdump/libpcap-1.8.0/
./configure --enable-shared=no
make
```
<img width="1308" height="265" alt="image" src="https://github.com/user-attachments/assets/8e9a3de4-009f-4f07-b477-df7e1ec91993" />

And yey : )

Now that the setup is complete, lets move on to generating an initial corpus for fuzzing

<img width="1884" height="884" alt="image" src="https://github.com/user-attachments/assets/b9c84055-32ae-4aa0-8c34-c81d6ff09082" />

## ASan 


AddressSanitizer (ASan) is a fast, compiler-based memory error detector built into Clang that helps catch critical memory safety bugs at runtime. By instrumenting the program during compilation and linking it with a lightweight runtime, ASan can reliably detect issues such as heap and stack out-of-bounds accesses, use-after-free, use-after-return, double frees, and memory leaks with a relatively low performance overhead of about 2x. Because it stops execution on the first detected error and produces precise, symbolized stack traces, AddressSanitizer is especially useful when compiling fuzzing targets, where crashing early and deterministically is more valuable than continuing execution in a corrupted state

### Building tcpdump and libpcap with AddressSanitizer Enabled

Now that the target and its dependencies are set up, the next step is to rebuild both **libpcap** and **tcpdump** with **AddressSanitizer (ASan)** enabled. This is a crucial step for fuzzing, as ASan allows us to catch memory safety bugs such as heap overflows, use after free, and use after return immediately when they occur, instead of letting the program continue in a corrupted state.



### Cleaning Previous Builds

Before enabling ASan, it is important to remove any artifacts produced by earlier, non-instrumented builds. Mixing sanitized and non-sanitized objects often leads to subtle issues and unreliable results during fuzzing.

We begin by deleting the previous installation prefix and cleaning both source trees.

```bash
rm -r $HOME/fuzzing_tcpdump/install
```

```bash
cd $HOME/fuzzing_tcpdump/libpcap-1.8.0/
make clean
```

```bash
cd $HOME/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/
make clean
```

At this point, both projects are back to a pristine state and ready to be rebuilt with instrumentation enabled.



### Building libpcap with ASan and AFL++

We first rebuild **libpcap**, since tcpdump links against it. For fuzzing, we want libpcap to be instrumented as well so that memory bugs inside packet parsing code are detectable.

We explicitly select the AFL++ LLVM-based compiler wrapper and configure libpcap to install into our isolated prefix.

```bash
cd $HOME/fuzzing_tcpdump/libpcap-1.8.0/
export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure \
  --enable-shared=no \
  --prefix="$HOME/fuzzing_tcpdump/install/"
```

The `--enable-shared=no` option ensures that a static libpcap is built, which avoids runtime issues when combining ASan with dynamically linked libraries during fuzzing.

We then compile libpcap with ASan enabled by setting `AFL_USE_ASAN=1`:

```bash
AFL_USE_ASAN=1 make
```

This causes AFL++ to automatically add the required `-fsanitize=address` flags and link against the AddressSanitizer runtime.



### Building tcpdump with ASan and AFL++

With libpcap built and installed into our custom prefix, we can now build **tcpdump** itself. As before, we use the AFL++ compiler wrapper and point the build system at the instrumented libpcap.

```bash
cd $HOME/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/
AFL_USE_ASAN=1 CC=afl-clang-lto ./configure \
  --prefix="$HOME/fuzzing_tcpdump/install/"
```

Once configured, we compile and install tcpdump with ASan enabled:

```bash
AFL_USE_ASAN=1 make
AFL_USE_ASAN=1 make install
```

At the end of this step, both tcpdump and libpcap are fully instrumented with AddressSanitizer and AFL++ coverage instrumentation. This gives us a high-signal fuzzing target where memory safety violations result in immediate, high-quality crashes that are easy to triage and reproduce.

### AFL++ Refusing to Start: A Beginner-Friendly Explanation

After building tcpdump and libpcap with AddressSanitizer and AFL++ instrumentation, the natural next step is to start fuzzing. Everything looks correct, the command is ready, and then… AFL++ suddenly aborts with a scary error message about `core_pattern`.


<img width="1889" height="625" alt="image" src="https://github.com/user-attachments/assets/75893468-f1ce-4e94-ac21-d48586f72cfd" />







AFL++ runs your program thousands of times per second with slightly broken inputs, hoping the program will crash.
When a crash happens, AFL++ needs to know **immediately** so it can:

* Save the crashing input
* Mark it as a real bug
* Move on to the next mutation



### What Is `core_pattern`?

On Linux, when a program crashes, the kernel follows a rule stored in:

```
/proc/sys/kernel/core_pattern
```

This rule tells the system **what to do when a crash happens**.

On many modern systems, this rule sends crash information to another program (like a crash reporter)



### Why ? 

When crashes are sent to an external program first, AFL++ does not hear about the crash instantly. That means:

* A real crash might look like a timeout
* The crash might be delayed or missed
* Fuzzing results become unreliable

Because of this, AFL++ checks your system setup at startup. If it sees that crashes are being “piped away”, it refuses to run and aborts with an error.

### The Fix 

We tell Linux to report crashes directly instead of sending them to another program.

Run this once:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```



### The Lazy shit 

If you are just playing around and do not care about missing crashes, you can tell AFL++ to ignore the problem:

```bash
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
```

Moving past that Let's start AFL and get fuzzing with the ASn enabled 



<img width="1430" height="630" alt="image" src="https://github.com/user-attachments/assets/caa66fbe-eab4-4b55-8b0f-bbeb540be1fc" />


## Some explanation on Adress San internals . 



For a small demo we i'll try explaining it through a program to demo the leak finding using clang sanitizer . 


<img width="1894" height="970" alt="image" src="https://github.com/user-attachments/assets/8984f175-c8e8-44e6-aecf-dd5d51b0a1a4" />



```bash
muffin@muffinn:/mnt/d/pwn$ clang -fsanitize=address -g memory-leak.c ; ASAN_OPTION=detect_leaks=1 ./a.out

=================================================================
==228472==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 7 byte(s) in 1 object(s) allocated from:
    #0 0x62e047f2c193 in malloc (/mnt/d/pwn/a.out+0xc6193) (BuildId: f2f2c331c2931debd20029b6da7b5dccfbfbfe97)
    #1 0x62e047f6a748 in main /mnt/d/pwn/memory-leak.c:8:6
    #2 0x7ce7f622a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #3 0x7ce7f622a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #4 0x62e047e91344 in _start (/mnt/d/pwn/a.out+0x2b344) (BuildId: f2f2c331c2931debd20029b6da7b5dccfbfbfe97)

SUMMARY: AddressSanitizer: 7 byte(s) leaked in 1 allocation(s).
```

AddressSanitizer exits on the first detected error. This is by design





