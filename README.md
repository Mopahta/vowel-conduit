# Vowel Conduit

A manual-mapping dll injector, which supports injecting into 32 and 64-bit processes.

## Build
```
g++ -o injector.exe src/*.h src/*.cpp
```
## Usage

```
injector.exe dll_path [process-name [dll_function_name]]
```