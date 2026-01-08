## Build Configuration

The target is compiled using AFL’s GCC wrapper with sanitizers and debug symbols enabled.

![AFL build output](https://github.com/user-attachments/assets/8010b3f4-c5ce-48be-b5cc-0926c8faacf2)



## Fuzzing Invocation

The fuzzer is launched with a minimal seed corpus. AFL detects available CPU cores and binds to a free core automatically.

![AFL startup and CPU binding](https://github.com/user-attachments/assets/ba77072c-a450-483d-b65a-6dce3f15c001)


## Fuzzing Behavior

As malformed inputs are generated, the program consistently crashes, with AFL identifying multiple unique crash conditions while producing thousands of total crash instances through continued mutation.

![AFL fuzzing results and crashes](https://github.com/user-attachments/assets/1f7d1af8-72cb-4a04-b14c-d89735d35de6)


## Crash Detection

The reported crashes are detected by sanitizers.

<img width="1379" height="271" alt="image" src="https://github.com/user-attachments/assets/47c400b4-c1fd-4936-bb3f-9f197da45e96" />
