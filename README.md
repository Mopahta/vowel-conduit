# Vowel Conduit

A manual-mapping dll injector, which supports injecting into 32 and 64-bit processes.

## Build
```
g++ -o injector.exe src/*.h src/*.cpp
```
## Usage

```
injector.exe dll_path [process_name [dll_function_name]]
```
*dll_path* - path to your dll

*process_name* [optional] - process name

*dll_function_name* [optional] - dll entry point function name accepting ***no parameters***, which name is *not mangled* after compilation. Instead, DllMain will be called.
