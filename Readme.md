## Rust-based Hasher Tool

An inital poke at using Rustlang to hash files (MD5, SHA1, SHA256, SHA512)

```
Usage:
  hasher.exe [OPTIONS]

Hash input file to stdio

Optional arguments:
  -h,--help             Show this help message and exit
  -f,--file FILE        Input file
  -d,--dir DIR          Input directory
  -b,--buffer BUFFER    Buffer size (bytes)
  -j, --json            JSON output
```