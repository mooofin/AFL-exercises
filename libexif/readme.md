
Some things to make clear that no two fuzzing sessions will be the same because AFL is non deterministic.


This time, we turn our attention to fuzzing libexif, the widely used EXIF metadata parsing library, with the goal of stress-testing how it handles malformed and unexpected image metadata. Since libexif processes complex, attacker-controlled binary structures embedded inside image files, it presents an ideal surface for discovering memory safety issues such as out-of-bounds reads, integer overflows, and use-after-free bug



## Lets set up our enviorment first

```bash
muffin@muffinn:/mnt/d$ cd $HOME
mkdir fuzzing_libexif && cd fuzzing_libexif/
muffin@muffinn:~/fuzzing_libexif$ wget https://github.com/libexif/libexif/archive/refs/tags/libexif-0_6_14-release.tar.gz
tar -xzvf libexif-0_6_14-release.tar.gz
--2026-01-11 05:40:23--  https://github.com/libexif/libexif/archive/refs/tags/libexif-0_6_14-release.tar.gz
Resolving github.com (github.com)... 20.207.73.82, 64:ff9b::14cf:4952
Connecting to github.com (github.com)|20.207.73.82|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/libexif/libexif/tar.gz/refs/tags/libexif-0_6_14-release [following]
--2026-01-11 05:40:24--  https://codeload.github.com/libexif/libexif/tar.gz/refs/tags/libexif-0_6_14-release
Resolving codeload.github.com (codeload.github.com)... 20.207.73.88, 64:ff9b::14cf:4958
Connecting to codeload.github.com (codeload.github.com)|20.207.73.88|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/x-gzip]
Saving to: ‘libexif-0_6_14-release.tar.gz’

libexif-0_6_14-release.tar.gz              [   <=>                                                                       ] 315.33K   641KB/s    in 0.5s

2026-01-11 05:40:26 (641 KB/s) - ‘libexif-0_6_14-release.tar.gz’ saved [322903]
```

<img width="1901" height="959" alt="image" src="https://github.com/user-attachments/assets/88e799e5-2bd6-4ff9-bc21-5fb1e926099c" />



## Then lets build and test the application

```bash
./configure --disable-docs --prefix=$PWD/install
make
make install
```

<img width="1893" height="912" alt="image" src="https://github.com/user-attachments/assets/900ac18c-2ef3-48c2-b222-4492aaacec3c" />

It's only the docs that did'nt get built so lets move on

---

Since libexif is a library, we'll need another application that makes use of this library and which will be fuzzed. For this task we're going to use exif command-line.

I went with this ;

<img width="1919" height="655" alt="image" src="https://github.com/user-attachments/assets/79a64884-8371-4641-9590-758a810e6c5f" />


## whats corpus ?

Corpus is basically a collection of inputs that the fuzzer will use as seeds . The fuzzer mutates these files to explore new code paths and trigger bugs.

We need a combination of good corpus and coverage to get the most out of fuzzing so a mix of seed corpus like

```bash
corpus/
├── img1.jpg
├── minimal_exif.jpg
├── truncated_ifd.jpg
└── weird_offsets.jpg
```

are good because they have a good validity to mutate accordingly , and get added back to the corpus again .

Let's get some inputs

```bash
cd $HOME/fuzzing_libexif
wget https://github.com/ianare/exif-samples/archive/refs/heads/master.zip
unzip master.zip
```



Yes and we can move onto AFL now

<img width="1912" height="491" alt="image" src="https://github.com/user-attachments/assets/4a9741d9-a1cf-43c6-9016-7631f2a5ee96" />



## Some more things to know

Fuzzing source code is a three-step process:

* Compile the target with a special compiler that prepares the target to be fuzzed efficiently. This step is called “instrumenting a target”.
* Prepare the fuzzing by selecting and optimizing the input corpus for the target.
* Perform the fuzzing of the target by randomly mutating input and assessing if that input was processed on a new path in the target binary.

AFL++ comes with a central compiler afl-cc that incorporates various different kinds of compiler targets and instrumentation options. The following evaluation flow will help you to select the best possible.

<img width="500" height="488" alt="image" src="https://github.com/user-attachments/assets/51d4e628-0b30-4503-a71d-56648df4a139" />



At a beginner level, you can think of fuzzing coverage as the fuzzer asking a very simple question over and over: *“Did the program do something new this time?”* Vanilla AFL answers this question using a small shared memory map and some random numbers that get baked into the binary during compilation. Each basic block in the program is given a random ID, and when the program jumps from one block to another, AFL combines the current and previous IDs and updates a slot in a 64 KB bitmap. You can roughly imagine the runtime logic as something like `map[(cur_id ^ prev_id) & 0xFFFF]++`. This works fine for small programs, but as soon as you fuzz a real target with thousands of blocks, many different edges end up writing to the same bitmap slot. From the fuzzer’s point of view, multiple distinct paths now look identical, so it stops rewarding inputs that actually explore new code.

You can see this behavior by building a target with classic AFL instrumentation. For example, compiling a program the old way looks like this:

```bash
export CC=afl-gcc
export CXX=afl-g++
./configure
make
```

At runtime, every execution updates the same fixed-size map, and collisions are inevitable. The fuzzer might mutate inputs for hours without realizing that it is technically reaching new logic, because the coverage feedback is too noisy. This is why fuzzing large libraries with vanilla AFL often plateaus early.

AFL++ fixes this by moving instrumentation to link time, using LLVM’s Link Time Optimization. Instead of assigning random IDs while compiling each source file independently, AFL++ waits until the linker has the full program in front of it. When you build in LTO mode, you typically do something like:

```bash
export CC=afl-clang-lto
export CXX=afl-clang-lto++
./configure --disable-shared
make
```

Under the hood, this causes all object files to be compiled into LLVM bitcode rather than final machine code. During the link step, AFL++ replaces the system linker with its own `afl-ld`. The LLVM linker then sees every function and every control-flow edge in the entire program and assigns a unique, deterministic ID to each edge. Because these IDs are planned globally, they do not collide in the coverage map. Internally, this is very similar to how LLVM’s own coverage works when you compile with `-fsanitize=coverage=edge`.

From the fuzzer’s perspective, this makes a huge difference. Now, when an input triggers a new path, AFL++ can clearly see a new edge being hit and will keep that input as interesting. You can even inspect the instrumentation being chosen by AFL++ at startup:

```bash
afl-fuzz -i corpus -o out -- ./target @@
```

You will see messages indicating that LTO-based, collision-free instrumentation is in use. The end result is that AFL++ gets a clean, high-resolution view of program behavior, allowing it to guide mutations far more intelligently. For a beginner, the takeaway is that vanilla AFL’s coverage is like a blurry heatmap where many paths overlap, while AFL++ with LTO gives you a sharp, accurate map of execution, which directly translates into better fuzzing results.



## Let's build it using afl-lto this time

```bash
rm -r $HOME/fuzzing_libexif/install
cd $HOME/fuzzing_libexif/libexif-libexif-0_6_14-release/
make clean
export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzzing_libexif/install/"
make
make install
```


And fuzz it 

<img width="1858" height="958" alt="image" src="https://github.com/user-attachments/assets/b41a5238-e4aa-4f32-b857-7c2587251834" />

```bash
afl-fuzz -i $HOME/fuzzing_libexif/exif-samples-master/jpg/ -o $HOME/fuzzing_libexif/out/ -s 123 -- $HOME/fuzzing_libexif/install/bin/exif @@
```

We do get some crashes but instaed of using gef like last time , we'll use eclipse IDE 


<img width="1008" height="714" alt="image" src="https://github.com/user-attachments/assets/b7ad6f99-e9aa-470a-9e2c-c9b0514cf51c" />



And open it 


<img width="1211" height="719" alt="image" src="https://github.com/user-attachments/assets/3ee733a6-029c-45fc-ac15-866b30737a1d" />



choose C/C++ -> "Existing code as makefile project". Then we need to select "Linux GCC"



<img width="689" height="572" alt="image" src="https://github.com/user-attachments/assets/332a2689-19b5-4b11-93f3-5a4fb8158df9" />


And click the project explorer 


<img width="1017" height="784" alt="image" src="https://github.com/user-attachments/assets/f431cb8f-068a-47a4-9d07-cf4d070d5fb1" />


Use the debug settings from here , 

<img width="1085" height="731" alt="image" src="https://github.com/user-attachments/assets/59f1ef14-7428-4bf3-8370-750e9e01b46d" />


We need to give the arguments of the crash to the debugger ;
```
muffin@muffinn:~/fuzzing_libexif/out/default/crashes$ ls
README.txt                                                                      id:000023,sig:11,src:000815,time:1969442,execs:1695366,op:havoc,rep:4
id:000000,sig:11,src:000002,time:5482,execs:5538,op:flip32,pos:707              id:000024,sig:11,src:000835,time:2113626,execs:1828903,op:havoc,rep:8
id:000001,sig:11,src:000002,time:5484,execs:5540,op:flip32,pos:719              id:000025,sig:11,src:000631,time:2208485,execs:1887093,op:havoc,rep:6
id:000002,sig:11,src:000002,time:11742,execs:11370,op:arith32,pos:34,val:-9     id:000026,sig:11,src:000872,time:2350026,execs:1976574,op:havoc,rep:7
id:000003,sig:11,src:000002,time:19506,execs:18791,op:havoc,rep:3               id:000027,sig:11,src:000872,time:2350454,execs:1976943,op:havoc,rep:2
id:000004,sig:11,src:000002,time:40736,execs:37405,op:havoc,rep:3               id:000028,sig:11,src:000871,time:2451781,execs:2050434,op:havoc,rep:1
id:000005,sig:11,src:000002,time:42758,execs:39273,op:havoc,rep:4               id:000029,sig:11,src:000781,time:2496223,execs:2079732,op:havoc,rep:11
id:000006,sig:11,src:000002,time:44412,execs:40654,op:havoc,rep:7               id:000030,sig:11,src:000897,time:2700414,execs:2216694,op:havoc,rep:6
id:000007,sig:11,src:000005,time:79592,execs:71711,op:arith32,pos:34,val:be:-9  id:000031,sig:11,src:000900,time:2770720,execs:2263746,op:havoc,rep:3
id:000008,sig:11,src:000007,time:138315,execs:127188,op:inf,rep:1               id:000032,sig:11,src:000918,time:3069941,execs:2501103,op:havoc,rep:9
id:000009,sig:11,src:000008,time:145380,execs:133020,op:flip32,pos:1141         id:000033,sig:11,src:000557,time:3305209,execs:2720118,op:havoc,rep:7
id:000010,sig:11,src:000022,time:153288,execs:139444,op:havoc,rep:8             id:000034,sig:11,src:000029,time:3995534,execs:3335299,op:havoc,rep:15
id:000011,sig:11,src:000042,time:167548,execs:151848,op:havoc,rep:3             id:000035,sig:11,src:000967,time:4009409,execs:3348305,op:havoc,rep:2
id:000012,sig:11,src:000085,time:191380,execs:171815,op:havoc,rep:7             id:000036,sig:11,src:000983,time:4382205,execs:3640984,op:havoc,rep:3
id:000013,sig:11,src:000085,time:204360,execs:181159,op:havoc,rep:14            id:000037,sig:11,src:000987,time:4466462,execs:3705557,op:havoc,rep:13
id:000014,sig:11,src:000497,time:614590,execs:532743,op:havoc,rep:1             id:000038,sig:11,src:000818,time:5235372,execs:4354123,op:havoc,rep:6
id:000015,sig:11,src:000281,time:1284590,execs:1157542,op:havoc,rep:9           id:000039,sig:11,src:001002,time:5696313,execs:4765548,op:havoc,rep:5
id:000016,sig:11,src:000688,time:1292284,execs:1165404,op:havoc,rep:7           id:000040,sig:11,src:000999,time:5805201,execs:4859084,op:havoc,rep:1
id:000017,sig:11,src:000688,time:1295490,execs:1169759,op:havoc,rep:11          id:000041,sig:11,src:000061,time:5978992,execs:5006835,op:havoc,rep:5
id:000018,sig:11,src:000721,time:1323786,execs:1200738,op:havoc,rep:6           id:000042,sig:11,src:000790,time:6020901,execs:5043916,op:havoc,rep:4
id:000019,sig:11,src:000746,time:1410128,execs:1283634,op:havoc,rep:16          id:000043,sig:11,src:000081,time:6545331,execs:5287820,op:havoc,rep:2
id:000020,sig:11,src:000552,time:1573330,execs:1402347,op:havoc,rep:16          id:000044,sig:11,src:000028,time:6713517,execs:5401827,op:havoc,rep:8
id:000021,sig:11,src:000552,time:1573386,execs:1402379,op:havoc,rep:5           id:000045,sig:11,src:000775,time:7532084,execs:6099251,op:havoc,rep:3
id:000022,sig:11,src:000630,time:1815249,execs:1567843,op:havoc,rep:1
```

<img width="1335" height="743" alt="image" src="https://github.com/user-attachments/assets/9ff5eac1-c006-4618-9df4-59076121fe6f" />

And we hit a breakpoint so let's try for a segfault 

<img width="1006" height="741" alt="image" src="https://github.com/user-attachments/assets/9d525170-0153-4318-b2be-ebdce3c37e2f" />



And we get one 


<img width="1832" height="117" alt="image" src="https://github.com/user-attachments/assets/28bedcf7-0913-4e2d-bf9d-ba712e81abba" />

Let's verify the crash with gef 

```bash
muffin@muffinn:~/fuzzing_libexif/exif-exif-0_6_15-release$ gdb ~/fuzzing_libexif/install/bin/exif
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffef7c00010  →  0x00000000007fff00
$rbx   : 0x0
$rcx   : 0x15
$rdx   : 0x3ddc
$rsp   : 0x00007fffffffd7a8  →  0x00005555555832b5  →  <exif_mnote_data_canon_load+02c5> mov edx, DWORD PTR [rsp+0x1c]
$rbp   : 0x1
$rsi   : 0x00005555557d1f89  →  0x0000000000000000
$rdi   : 0x00007ffef7c185c0  →  0x0000000000000000
$rip   : 0x00007ffff7d88fe8  →  <__memmove_avx_unaligned_erms+05a8> vmovdqu ymm15, YMMWORD PTR [rsi+0x3060]
$r8    : 0xffffffffffffffd0
$r9    : 0x00005555555be73f  →  0x0000000000000001
$r10   : 0x3fff9
$r11   : 0x6a00000
$r12   : 0x00005555557bb690  →  0x00005555557bb720  →  0x0000000000000001
$r13   : 0x00005555557b9620  →  0x4949000066697845 ("Exif"?)
$r14   : 0x00005555555b2930  →  0x0000000000000000
$r15   : 0xffffffffffffff90
$eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd7a8│+0x0000: 0x00005555555832b5  →  <exif_mnote_data_canon_load+02c5> mov edx, DWORD PTR [rsp+0x1c]       ← $rsp
0x00007fffffffd7b0│+0x0008: 0x00005555557b9620  →  0x4949000066697845 ("Exif"?)
0x00007fffffffd7b8│+0x0010: 0x00000cad557bb690
0x00007fffffffd7c0│+0x0018: 0x00005555557b8a50  →  0x0000000300000000
0x00007fffffffd7c8│+0x0020: 0x0000000e000003b9
0x00007fffffffd7d0│+0x0028: 0x0000555555582000  →  <exif_mnote_data_canon_count+0000> endbr64
0x00007fffffffd7d8│+0x0030: 0x00005555555b2930  →  0x0000000000000000
0x00007fffffffd7e0│+0x0038: 0xffffffffffffff90
──────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7d88fd6 <__memmove_avx_unaligned_erms+0596> add    BYTE PTR [rax], al
   0x7ffff7d88fd8 <__memmove_avx_unaligned_erms+0598> vmovdqu ymm13, YMMWORD PTR [rsi+0x3020]
   0x7ffff7d88fe0 <__memmove_avx_unaligned_erms+05a0> vmovdqu ymm14, YMMWORD PTR [rsi+0x3040]
 → 0x7ffff7d88fe8 <__memmove_avx_unaligned_erms+05a8> vmovdqu ymm15, YMMWORD PTR [rsi+0x3060]
   0x7ffff7d88ff0 <__memmove_avx_unaligned_erms+05b0> sub    rsi, 0xffffffffffffff80
   0x7ffff7d88ff4 <__memmove_avx_unaligned_erms+05b4> vmovntdq YMMWORD PTR [rdi], ymm0
   0x7ffff7d88ff8 <__memmove_avx_unaligned_erms+05b8> vmovntdq YMMWORD PTR [rdi+0x20], ymm1
   0x7ffff7d88ffd <__memmove_avx_unaligned_erms+05bd> vmovntdq YMMWORD PTR [rdi+0x40], ymm2
   0x7ffff7d89002 <__memmove_avx_unaligned_erms+05c2> vmovntdq YMMWORD PTR [rdi+0x60], ymm3
──────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exif", stopped 0x7ffff7d88fe8 in __memcpy_avx_unaligned_erms (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7d88fe8 → __memcpy_avx_unaligned_erms()
[#1] 0x5555555832b5 → memcpy(__len=<optimized out>, __src=<optimized out>, __dest=<optimized out>)
[#2] 0x5555555832b5 → exif_mnote_data_canon_load(ne=0x5555557bb690, buf=<optimized out>, buf_size=<optimized out>)
[#3] 0x5555555705c9 → exif_data_load_data(data=0x5555557b8610, d_orig=<optimized out>, ds_orig=<optimized out>)
[#4] 0x55555557d67d → exif_loader_get_data(loader=0x5555557b85c0)
[#5] 0x55555555f3af → main(argc=<optimized out>, argv=<optimized out>)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
```bash
gef➤  bt
#0  0x00007ffff7d88fe8 in __memcpy_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:833
#1  0x00005555555832b5 in memcpy (__len=<optimized out>, __src=<optimized out>, __dest=<optimized out>)
    at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:29
#2  exif_mnote_data_canon_load (ne=0x5555557bb690, buf=<optimized out>, buf_size=<optimized out>)
    at exif-mnote-data-canon.c:224
#3  0x00005555555705c9 in exif_data_load_data (data=data@entry=0x5555557b8610, d_orig=<optimized out>,
    ds_orig=<optimized out>) at exif-data.c:867
#4  0x000055555557d67d in exif_loader_get_data (loader=loader@entry=0x5555557b85c0) at exif-loader.c:387
#5  0x000055555555f3af in main (argc=<optimized out>, argv=<optimized out>) at main.c:438

```

The crash occurs inside memcpy, which immediately suggests a memory safety violation. Since memcpy performs no bounds checking, a segmentation fault here usually indicates that either the source pointer, destination pointer, or length argument is invalid. In fuzzing contexts, this almost always points to attacker-controlled size or offset fields being trusted without sufficient validation.

The most important frame is frame #2:
exif_mnote_data_canon_load at line 224. This function is responsible for parsing Canon-specific MakerNote EXIF data. MakerNotes are vendor-specific metadata blocks embedded inside EXIF, and they are historically one of the most error-prone parts of image parsers due to their lack of strict standardization. Seeing a crash here is a strong signal that malformed MakerNote data is triggering unsafe memory operations.

The call stack also shows how execution reached this point. The malformed input is processed by exif_data_load_data, which is the main EXIF parsing entry point. From there, control flows through the EXIF loader and eventually into the Canon MakerNote parser. This confirms that the crash is not caused by command-line argument handling or CLI glue code, but by core libexif parsing logic.

Given that the fault occurs during a memcpy inside the MakerNote parser, the most likely root cause is an out-of-bounds read or write. This typically happens when length fields embedded in the EXIF data are used directly to determine how many bytes to copy, without checking whether those bytes actually exist within the input buffer. Depending on whether the invalid access occurs on the source or destination side of memcpy, this can result in an out-of-bounds read or an out-of-bounds write. Either case represents a serious memory safety issue


## References

* **libexif Canon MakerNote fix**
  [https://github.com/libexif/libexif/commit/8ce72b7f81e61ef69b7ad5bdfeff1516c90fa361](https://github.com/libexif/libexif/commit/8ce72b7f81e61ef69b7ad5bdfeff1516c90fa361)
  Patch addressing unsafe handling of Canon MakerNote data in libexif, related to missing bounds checks during EXIF parsing.

* **AFL++ LTO instrumentation documentation**
  [https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md)
  Official documentation describing AFL++ link-time optimization (LTO) based instrumentation for collision-free edge coverage.

* **AFL++ laf-intel instrumentation documentation**
  [https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md)
  Documentation for laf-intel, an AFL++ instrumentation mode that improves coverage in comparison-heavy code.

* **laf-intel project blog**
  [https://lafintel.wordpress.com](https://lafintel.wordpress.com)
  Background and design rationale for laf-intel, explaining how it helps fuzzers overcome comparison bottlenecks.





















