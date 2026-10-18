# runtime-monitor

Per-process file-behavior collector and feature extractor (`app/`).

| OS      | Live source                          | Privileges                                   |
|---------|--------------------------------------|----------------------------------------------|
| Linux   | `/proc/<pid>/{stat,io,fd}` sampling  | root to see other users' processes           |
| Windows | ETW `Microsoft-Windows-Kernel-File`  | Administrator (ETW session)                  |

`replay` and `synth` work on any OS.

## Install

Prerequisite: Rust toolchain (https://rustup.rs). On Windows use the MSVC toolchain plus Visual Studio Build Tools (C++ workload).

Linux:
```sh
./scripts/install.sh
```

Windows (PowerShell):
```powershell
.\scripts\install.ps1
```

Either script runs `cargo install --path app --locked`, placing `runtime-monitor` in `~/.cargo/bin` (`%USERPROFILE%\.cargo\bin`), which rustup adds to `PATH`.

## Use

```
runtime-monitor live --duration-secs 60 --label benign   # Windows: run from an Administrator shell
runtime-monitor synth --scenario <name> --out s.jsonl
runtime-monitor replay --in s.jsonl
```

Output goes to `out/<execution-id>/` (override with `--out`).

## Status

The Windows ETW source compiles (`cargo check --target x86_64-pc-windows-gnu`) but has not been run on Windows; see the header of `app/src/source/etw.rs`.
