
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

```bash
afl-fuzz -i $HOME/fuzzing_libexif/exif-samples-master/jpg/ -o $HOME/fuzzing_libexif/out/ -s 123 -- $HOME/fuzzing_libexif/install/bin/exif @@
```

<img width="1887" height="972" alt="image" src="https://github.com/user-attachments/assets/e4cfbcf2-e71c-43be-9554-24d2ee3ffa79" />

