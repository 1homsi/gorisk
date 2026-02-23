# Capability Detection Reference

gorisk detects nine capability types across 22 programming languages. This document
explains what each capability means, how detection works at each analysis layer, and
provides a per-language reference for imports and call-site patterns.

---

## Capabilities

| Capability | Weight | What it means |
|-----------|--------|---------------|
| `unsafe`  | 25 | Bypasses type/memory safety (pointer casts, FFI, eval, deserialization) |
| `exec`    | 20 | Spawns subprocesses or shell commands |
| `plugin`  | 20 | Loads or executes external code at runtime (dlopen, dynamic import) |
| `network` | 15 | Makes outbound or inbound network connections |
| `fs:write`| 10 | Writes, creates, or deletes files |
| `fs:read` |  5 | Reads from the filesystem |
| `crypto`  |  5 | Uses cryptographic primitives |
| `env`     |  5 | Reads environment variables |
| `reflect` |  5 | Uses runtime reflection or introspection |

**Risk thresholds** (cumulative score):

| Level  | Score |
|--------|-------|
| LOW    | < 10  |
| MEDIUM | ≥ 10  |
| HIGH   | ≥ 30  |

---

## Detection Pipeline

gorisk uses three analysis layers, each increasing in precision:

### Layer 1 — Lockfile / Manifest (all languages)

The package name is matched against the `imports` map in `languages/<lang>.yaml`.
A matched package contributes capabilities at **confidence 0.90**.

```
package-lock.json / Cargo.lock / go.sum / ...
        ↓
  package name → imports map → capabilities
```

### Layer 2 — Static Source Scan (all languages)

Every source file is scanned line-by-line. Two checks run per line:

- **Import statement** — `import X`, `use X`, `require X`, etc. Matched against
  the `imports` map. Confidence **0.90**.
- **Call-site pattern** — Substring match against the `call_sites` map in the
  YAML. Confidence **0.75** (Go/JVM) or **0.60** (Node.js, PHP regex fallback).

### Layer 3 — Interprocedural AST (22 languages)

Regex-based function boundaries are detected in source files. A function-level
call graph (IR) is built and fed to the k=1 CFA interprocedural engine:

```
source files → function boundaries → DirectCaps per function
                                   → CallEdges between functions
                                          ↓
                              interproc fixpoint (Tarjan SCC + worklist)
                                          ↓
                              TransitiveCaps propagated across call graph
```

Hop multipliers reduce confidence with distance:

| Hops | Multiplier |
|------|-----------|
| 0    | 1.00      |
| 1    | 0.70      |
| 2    | 0.55      |
| 3+   | 0.40      |

Maximum propagation depth: 3 hops.

---

## Language Reference

### Go

**Source:** `*.go` | **Analysis depth:** Full (AST + SSA callgraph + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| Import path     | 0.90       |
| `pkg.Func()` call | 0.75     |
| Interprocedural | hop × base |

**Key import → capability mappings:**

| Import | Capabilities |
|--------|-------------|
| `os` | `fs:read`, `fs:write`, `env` |
| `os/exec` | `exec` |
| `net/http` | `network` |
| `unsafe` | `unsafe` |
| `reflect` | `reflect` |
| `plugin` | `plugin` |
| `crypto/*` | `crypto` |
| `database/sql` | `network` |
| `golang.org/x/crypto/ssh` | `network`, `crypto` |

**Key call-site patterns:** `exec.Command(`, `os.ReadFile(`, `os.WriteFile(`,
`http.Get(`, `tls.Dial(`, `os.Getenv(`, `reflect.TypeOf(`

---

### Node.js / TypeScript

**Source:** `*.js`, `*.ts`, `*.mjs`, `*.cjs` | **Analysis depth:** Full (regex AST + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| `require()` / `import` | 0.90 |
| Chained call `require('x').y()` | 0.80 |
| Variable call `cp.exec()` | 0.85 |
| Destructured `{ exec }` | 0.85 |
| Plain callsite regex | 0.60 |

**Key imports:** `child_process` → `exec`; `fs` → `fs:read`, `fs:write`;
`net`/`http`/`https` → `network`; `crypto` → `crypto`; `vm` → `unsafe`;
`worker_threads` → `exec`; `module` → `plugin`

---

### Python

**Source:** `*.py` | **Analysis depth:** Full (indent-based function detection + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| `import X` / `from X import Y` | 0.90 |
| Call-site substring | 0.75 |
| Interprocedural | hop × base |

**Key imports:**

| Import | Capabilities |
|--------|-------------|
| `subprocess` | `exec` |
| `os` | `fs:read`, `fs:write`, `env`, `exec` |
| `socket` | `network` |
| `requests` / `httpx` | `network` |
| `hashlib` / `cryptography` | `crypto` |
| `pickle` / `ctypes` | `unsafe` |
| `importlib` | `plugin` |
| `inspect` / `types` | `reflect` |

**Key call-sites:** `subprocess.run(`, `os.system(`, `eval(`, `exec(`,
`open(`, `os.getenv(`, `importlib.import_module(`

---

### Ruby

**Source:** `*.rb` | **Analysis depth:** Full (keyword-block function detection + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| `require` gem name | 0.90 |
| Call-site substring | 0.75 |

**Key imports:**

| Gem | Capabilities |
|-----|-------------|
| `open3` / `shellwords` | `exec` |
| `faraday` / `httparty` | `network` |
| `openssl` | `crypto`, `network` |
| `fileutils` | `fs:read`, `fs:write` |
| `marshal` | `unsafe` |
| `rails` | `network`, `fs:read`, `fs:write`, `exec` |

**Key call-sites:** `` ` `` (backtick), `system(`, `exec(`, `eval(`,
`Marshal.load(`, `File.read(`, `ENV[`, `Net::HTTP.`

---

### PHP

**Source:** `*.php` | **Analysis depth:** Standard (regex function detection + k=1 CFA)

**Key imports:** `guzzlehttp/guzzle` → `network`; `symfony/process` → `exec`;
`league/flysystem` → `fs:read`, `fs:write`; `defuse/php-encryption` → `crypto`

**Key call-sites:** `exec(`, `shell_exec(`, `system(`, `passthru(`,
`eval(`, `file_get_contents(`, `getenv(`, `openssl_encrypt(`

---

### Java

**Source:** `*.java` | **Analysis depth:** Full (method-declaration regex + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| `import` statement | 0.90 |
| Call-site substring | 0.75 |

**Key imports:**

| Package | Capabilities |
|---------|-------------|
| `java.io`, `java.nio` | `fs:read`, `fs:write` |
| `java.net`, `javax.net.ssl` | `network` |
| `java.lang.ProcessBuilder` | `exec` |
| `java.security`, `javax.crypto` | `crypto` |
| `java.lang.reflect` | `reflect` |
| `sun.misc.Unsafe` | `unsafe` |
| `java.lang.ClassLoader` | `plugin` |
| `java.io.ObjectInputStream` | `unsafe` |

**Key call-sites:** `new ProcessBuilder(`, `Runtime.getRuntime().exec(`,
`System.getenv(`, `Cipher.getInstance(`, `Class.forName(`, `Method.invoke(`

---

### Kotlin

**Source:** `*.kt`, `*.kts` | **Analysis depth:** Full (fun-declaration regex + k=1 CFA)

Detection is via Gradle group:artifact coordinates from `build.gradle.kts`,
`build.gradle`, or `libs.versions.toml`.

**Key imports (Gradle coordinates → capabilities):**

| Artifact | Capabilities |
|----------|-------------|
| `io.ktor:ktor-client-core` | `network` |
| `com.squareup.okhttp3:okhttp` | `network` |
| `org.bouncycastle:bcprov-jdk18on` | `crypto` |
| `com.sun.jna:jna` | `unsafe` |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` | `exec` |

**Key call-sites:** same as Java (`ProcessBuilder(`, `System.getenv(`,
`MessageDigest.getInstance(`, `Cipher.getInstance(`, `Class.forName(`)

---

### Scala

**Source:** `*.scala` | **Analysis depth:** Full (def-declaration regex + k=1 CFA)

**Key imports:** Same JVM ecosystem as Java/Kotlin — `java.io`, `java.net`,
`javax.crypto`, `org.apache.http`, `akka`, `play`, `slick`, `cats-effect`

**Key call-sites:** `ProcessBuilder(`, `System.getenv(`, `MessageDigest.getInstance(`,
`Cipher.getInstance(`, `Source.fromFile(`, `Files.write(`

---

### Rust

**Source:** `*.rs` | **Analysis depth:** Full (fn-declaration regex + k=1 CFA)

| Detection method | Confidence |
|-----------------|-----------|
| `use`/`extern crate` | 0.90 |
| Call-site substring | 0.75 |

**Key imports:**

| Crate | Capabilities |
|-------|-------------|
| `reqwest` / `hyper` / `tokio` | `network` |
| `std::fs` | `fs:read`, `fs:write` |
| `std::process` | `exec` |
| `ring` / `rustls` / `openssl` | `crypto` |
| `libc` / `nix` / `winapi` | `unsafe` |
| `libloading` | `plugin` |
| `serde` / `serde_json` | `reflect` |

**Key call-sites:** `Command::new(`, `std::env::var(`, `std::fs::read(`,
`unsafe {`, `libloading::Library::new(`

---

### Haskell

**Source:** `*.hs`, `*.lhs` | **Analysis depth:** Full (type-sig + def detection + k=1 CFA)

**Key imports:** `Network.HTTP.Client` / `wreq` / `req` → `network`;
`System.Process` → `exec`; `System.Environment` → `env`;
`Crypto.Hash` / `Crypto.Cipher` → `crypto`; `System.IO` → `fs:read`, `fs:write`;
`Foreign` / `Foreign.C` → `unsafe`; `Data.Dynamic` / `GHC.Generics` → `reflect`

**Key call-sites:** `createProcess`, `rawSystem`, `getEnv`, `openFile`,
`hGetContents`, `connectTo`, `hPutStrLn`

---

### OCaml

**Source:** `*.ml`, `*.mli` | **Analysis depth:** Full (let-binding detection + k=1 CFA)

**Key imports:** `Lwt_io` / `Cohttp_lwt_unix` → `network`; `Unix` → `exec`,
`fs:read`, `fs:write`; `Nocrypto` / `Mirage_crypto` → `crypto`;
`Dynlink` → `plugin`; `Obj` → `unsafe`

**Key call-sites:** `Unix.create_process`, `Sys.getenv`, `open_in`,
`open_out`, `Dynlink.loadfile`, `Obj.magic`

---

### Elixir

**Source:** `*.ex`, `*.exs` | **Analysis depth:** Full (def/defp detection + k=1 CFA)

**Key imports (Hex packages):**

| Package | Capabilities |
|---------|-------------|
| `httpoison` / `tesla` / `req` | `network` |
| `phoenix` | `network`, `fs:read`, `fs:write`, `exec` |
| `ecto` / `postgrex` | `network` |
| `bcrypt_elixir` / `guardian` | `crypto` |
| `porcelain` / `erlexec` | `exec` |

**Key call-sites:** `System.cmd(`, `:os.cmd(`, `System.get_env(`,
`File.read(`, `File.write(`, `:crypto.hash(`, `Code.eval_string(`,
`:erlang.binary_to_term(`, `Port.open(`

---

### Erlang

**Source:** `*.erl`, `*.hrl` | **Analysis depth:** Full (function-clause detection + k=1 CFA)

**Key imports:** `inets` / `httpc` → `network`; `ssl` → `network`, `crypto`;
`os` → `exec`, `env`; `file` → `fs:read`, `fs:write`; `crypto` → `crypto`;
`code` → `plugin`

**Key call-sites:** `os:cmd(`, `os:getenv(`, `file:read_file(`,
`file:write_file(`, `crypto:hash(`, `ssl:connect(`, `code:load_file(`

---

### Clojure

**Source:** `*.clj`, `*.cljs`, `*.cljc` | **Analysis depth:** Full (defn-form detection + k=1 CFA)

**Key imports (Leiningen/deps.edn coordinates):**
`org.clojure/clojure` → `reflect`; `http-kit` / `clj-http` → `network`;
`cheshire` → `fs:read`; `clojure.java.io` → `fs:read`, `fs:write`;
`clojure.java.shell` → `exec`; `crypto-equality` → `crypto`

**Key call-sites:** `clojure.java.shell/sh`, `System/getenv`, `slurp`,
`spit`, `clojure.java.io/reader`, `eval`, `load-file`, `import`

---

### Swift

**Source:** `*.swift` | **Analysis depth:** Full (func-declaration regex + k=1 CFA)

**Key imports:**

| Module / Package | Capabilities |
|-----------------|-------------|
| `Foundation` | `fs:read`, `fs:write`, `network`, `exec`, `env` |
| `Alamofire` / `URLSession` | `network` |
| `CryptoKit` / `JWTKit` | `crypto` |
| `AppKit` / `SwiftShell` | `exec` |
| `Mirror` | `reflect` |

**Key call-sites:** `URLSession.shared`, `FileManager.default`,
`Process(`, `ProcessInfo.processInfo.environment`,
`SHA256.hash(`, `UnsafeMutablePointer(`, `dlopen(`, `NSClassFromString(`

---

### Dart / Flutter

**Source:** `*.dart` | **Analysis depth:** Full (function-declaration regex + k=1 CFA)

**Key imports:** `dart:io` → `fs:read`, `fs:write`, `network`, `exec`;
`http` / `dio` → `network`; `dart:crypto` / `pointycastle` → `crypto`;
`dart:mirrors` → `reflect`; `dart:ffi` → `unsafe`; `flutter_secure_storage` → `crypto`

**Key call-sites:** `File(`, `HttpClient(`, `Process.run(`,
`Platform.environment`, `sha256.convert(`, `Pointer.fromAddress(`,
`DynamicLibrary.open(`

---

### C# / .NET

**Source:** `*.cs` | **Analysis depth:** Full (method-declaration regex + k=1 CFA)

**Key imports (NuGet packages):**

| Package | Capabilities |
|---------|-------------|
| `System.Net.Http` / `RestSharp` | `network` |
| `System.IO` | `fs:read`, `fs:write` |
| `System.Diagnostics.Process` | `exec` |
| `System.Security.Cryptography` / `BouncyCastle` | `crypto` |
| `System.Reflection` | `reflect` |

**Key call-sites:** `Process.Start(`, `File.ReadAllText(`, `File.WriteAllText(`,
`Environment.GetEnvironmentVariable(`, `new HttpClient(`, `Assembly.Load(`,
`SHA256.Create(`, `Marshal.AllocHGlobal(`

---

### C / C++

**Source:** `*.c`, `*.cpp`, `*.cc`, `*.cxx`, `*.h`, `*.hpp`
**Analysis depth:** Full (function-definition regex + k=1 CFA)

**Key imports (vcpkg/conan package names):**

| Package | Capabilities |
|---------|-------------|
| `curl` / `libcurl` | `network` |
| `openssl` / `libsodium` | `crypto` |
| `sqlite3` / `leveldb` | `fs:read`, `fs:write` |
| `libloading` / `dlfcn` | `plugin`, `unsafe` |
| `libffi` | `unsafe`, `plugin` |

**Key call-sites:**

| Pattern | Capabilities |
|---------|-------------|
| `system(`, `popen(`, `execve(`, `fork(` | `exec` |
| `getenv(`, `setenv(` | `env` |
| `fopen(`, `fread(`, `fwrite(` | `fs:read`/`fs:write` |
| `socket(`, `connect(`, `bind(` | `network` |
| `dlopen(`, `LoadLibrary(` | `plugin`, `unsafe` |
| `mmap(`, `reinterpret_cast<` | `unsafe` |

---

### Julia

**Source:** `*.jl` | **Analysis depth:** Full (function-keyword detection + k=1 CFA)

**Key imports:**

| Package | Capabilities |
|---------|-------------|
| `HTTP` / `Downloads` | `network` |
| `Sockets` | `network` |
| `SHA` / `OpenSSL` / `MbedTLS` | `crypto` |
| `Libdl` | `plugin`, `unsafe` |
| `Distributed` / `Threads` | `exec` |
| `Pkg` / `Conda` | `exec`, `network` |

**Key call-sites:** `run(\``, `HTTP.get(`, `ENV[`, `open(`, `write(`,
`ccall(`, `dlopen(`, `sha256(`

---

### R

**Source:** `*.r`, `*.R` | **Analysis depth:** Full (assignment-function detection + k=1 CFA)

**Key imports (CRAN packages):**

| Package | Capabilities |
|---------|-------------|
| `httr` / `httr2` / `curl` | `network` |
| `readr` / `data.table` | `fs:read` |
| `DBI` / `RSQLite` | `network`, `fs:read`, `fs:write` |
| `sodium` / `openssl` | `crypto` |
| `processx` / `callr` | `exec` |
| `Rcpp` | `unsafe` |

**Key call-sites:** `system(`, `system2(`, `Sys.getenv(`, `readLines(`,
`read.csv(`, `GET(`, `POST(`, `download.file(`, `source(`,
`eval(parse(`, `dyn.load(`, `library(`, `require(`

---

### Perl

**Source:** `*.pl`, `*.pm`, `*.t` | **Analysis depth:** Full (sub-declaration detection + k=1 CFA)

**Key imports (CPAN modules):**

| Module | Capabilities |
|--------|-------------|
| `LWP::UserAgent` / `HTTP::Tiny` | `network` |
| `IO::Socket::SSL` | `network`, `crypto` |
| `Digest::SHA` / `Crypt::OpenSSL::RSA` | `crypto` |
| `IPC::Open3` / `POSIX` | `exec` |
| `DBI` | `network`, `fs:read` |
| `Moose` / `Class::MOP` | `reflect`, `plugin` |
| `Inline::C` | `unsafe`, `plugin` |

**Key call-sites:** `system(`, `exec(`, `` ` `` (backtick), `qx{`,
`$ENV{`, `open(`, `eval `, `require `, `use `, `Digest::SHA->new`

---

### Lua

**Source:** `*.lua` | **Analysis depth:** Full (function-keyword detection + k=1 CFA)

**Key imports (LuaRocks packages):** `lua-http` / `socket` → `network`;
`luacrypto` / `luaossl` → `crypto`; `lfs` → `fs:read`, `fs:write`;
`luasql-sqlite3` → `network`, `fs:read`, `fs:write`

**Key call-sites:** `os.execute(`, `io.popen(`, `os.getenv(`, `io.open(`,
`io.read(`, `io.write(`, `require(`, `load(`, `loadstring(`, `dofile(`

---

## Confidence Levels Summary

| Evidence type | Confidence |
|---------------|-----------|
| Lockfile / manifest package name | 0.90 |
| `import` statement in source | 0.90 |
| Install script (`postinstall` etc.) | 0.85 |
| AST: destructured import binding | 0.85 |
| AST: variable call resolved via binding | 0.85 |
| AST: chained require call | 0.80 |
| Call-site pattern match (Go / JVM / systems) | 0.75 |
| Call-site pattern match (Node fallback / PHP) | 0.60 |
| Interprocedural (1 hop, base 0.75) | 0.53 |
| Interprocedural (2 hops, base 0.75) | 0.41 |
| Interprocedural (3 hops, base 0.75) | 0.30 |

---

## Extending Patterns

Patterns live in `languages/<lang>.yaml`. Each file has two sections:

```yaml
imports:
  package-name: [capability, ...]

call_sites:
  "substring to match(": [capability, ...]
```

**Rules:**
- Import keys are matched as **exact strings** (or prefix for some languages).
- Call-site keys are matched as **substrings** of each source line — be specific
  to avoid false positives (e.g. `"os.exec("` not `"exec("`).
- After editing a YAML, run `go test ./languages/ ./internal/capability/...` to
  verify the file loads correctly.
- Run `gorisk scan` on the target project to validate detection quality.

See `docs/false-positives.md` for guidance on tuning patterns that generate noise.
