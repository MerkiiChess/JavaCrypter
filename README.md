# JavaCrypter

A bytecode-level protection tool for Java jars. It rewrites a jar in two ways:

- **Opcode substitution** - a handful of standard JVM opcodes (`return`, `invokevirtual`,
  `dup`, ...) get remapped to custom values that only a matching, patched JVM knows how
  to execute. A stock JVM (or a decompiler) can't load the result.
- **String encryption** - every string constant in the bytecode is encrypted with
  AES-GCM at protect time. A small decryptor class gets embedded into the output jar
  and each `ldc "some string"` is replaced with a call into it, so plaintext strings
  never sit in the class files.

Classes are also written out in a different order than they came in (ranked by
inheritance depth instead of the source jar's original layout), so a naive diff
against the original jar doesn't line up entry for entry.

This is the build-time half of a licensing/anti-tamper setup. The runtime half - the
thing that lets a protected jar actually run - is a small Java agent shipped in the
same repo (`ru.merkii.crypt.agent`), not a patched JVM. It is **not** an antivirus-evasion
tool and it does not try to defeat someone who can attach a debugger to the agent - it
raises the cost of casual decompilation, nothing more.

## How it works

```
input.jar
  │
  ├─ non-.class entries  ───────────────────────────► copied through unchanged
  │
  └─ .class entries ─► parsed with ASM
                          │
                          ├─ opcode substitution (JarProtector.substituteOpcodes)
                          ├─ string constants → AES-GCM ciphertext + decrypt() call
                          │  (JarProtector.encryptStringConstants)
                          └─ written out in inheritance-depth order
                                                          │
                                                          ▼
                                              output_crypted.jar
                                              + StringDecryptor.class
                                              + key.bin (AES key for this run)
```

The mapping itself lives in `OpcodeTable`, shared by both sides so they can't drift
apart, and it's intentionally not randomized between runs.

## Running a protected jar

A jar produced by `protect` fails to load on a stock JVM - the verifier rejects the
substituted opcodes outright (`VerifyError: Bad instruction`), before your code ever
runs. To actually run it, attach the reversal agent built by this project:

```
java -javaagent:JavaCrypter-<version>-agent.jar[=some/package/prefix/] -jar app_crypted.jar
```

The agent hooks `java.lang.instrument.ClassFileTransformer` and, for every class
whose name matches the given prefix (or every application class if you don't pass
one), restores the substituted opcodes back to their real values *before* the JVM's
own class-file verifier looks at the bytes. Everything after that - verification,
interpretation, JIT compilation - runs completely unmodified on a normal OpenJDK
build. No JVM source patching, no per-platform native builds.

ASM itself can't be used for this - it throws while decoding the very first
instruction it doesn't recognize - so the agent has its own minimal, ASM-free
class-file reader (`RawClassFile`) that walks the JVM spec's per-opcode instruction
layout by hand just far enough to find and byte-swap the substituted opcodes back.
Since substitution never changes an instruction's length, this is a pure in-place
patch - nothing else in the class file needs to move or be resized.

## Requirements

- Java 21+ for building/running this project.
- Whatever JVM the *protected app* targets just needs to be a stock JDK with the
  reversal agent attached - see above.

## Usage

```bash
./gradlew build

# protect a jar: opcode substitution + string encryption
./gradlew run --args="protect path/to/app.jar"
# → path/to/app_crypted.jar

# pull every non-.class entry (configs, assets, ...) into its own jar
./gradlew run --args="export-assets path/to/app.jar"
# → path/to/app_assetsExported.jar
```

## Project layout

```
ru.merkii.crypt
├── Main.java              CLI entry point, dispatches to the two commands
├── JarProtector.java       core: opcode substitution, string encryption, class ordering
├── AssetExporter.java      export-assets command
├── OpcodeTable.java        the substitution mapping - shared by JarProtector and the agent
├── OpcodeSubstitution.java one entry in the opcode remap table, with an applied-count
├── ClassPair.java          class + write-order priority, used to sort before writing
├── IoUtil.java             stream copy helper
├── crypt/
│   ├── StringEncryptor.java   build-time AES-GCM encryption
│   ├── StringDecryptor.java   embedded verbatim into every protected jar
│   └── EncryptionStats.java   tracks what got encrypted, for the summary printout
└── agent/                  packaged separately as <artifact>-agent.jar, see above
    ├── OpcodeRestoringAgent.java   premain entry point, registers the transformer
    ├── RawClassFile.java          hand-rolled class-file reader/patcher (no ASM)
    └── ReverseOpcodeMap.java      OpcodeTable, inverted for restoration
```

## Testing

```bash
./gradlew test
```

`JarProtectorTest` is a regression test for the two bugs that used to make
`protect` unusable: writing directly to `AbstractInsnNode.opcode` (package-private
in ASM, doesn't compile) and asking `ClassWriter` to `COMPUTE_MAXS` on an opcode
outside its known range (throws `ArrayIndexOutOfBoundsException`). It checks the
raw output bytes rather than reading the protected class back in with ASM, since
being unparseable by stock tooling is the whole point.

`StringEncryptorTest` covers the AES round trip and confirms encrypting the same
string twice never produces the same ciphertext (fresh nonce per call).

`RawClassFileTest` runs the whole pipeline end to end: builds a class with a
`lookupswitch` and a substituted `bipush` in the same method (to make sure the
agent's walker steps over the switch's padding/table correctly before it gets back
to spotting substituted opcodes), protects it through the real `Main` → `JarProtector`
path, restores it with `RawClassFile`, then actually loads and executes the result -
not just diffs bytes - to prove the round trip produces working code.

## Notes on the string encryption

The AES key travels inside the output jar (`key.bin`, next to `StringDecryptor.class`)
so the protected app can decrypt its own strings at runtime. That's the standard
tradeoff for any client-side protection scheme - it stops someone from just grepping
the jar for strings, but the key is reachable by anyone willing to unzip the jar and
read it. Similarly, the agent's own jar is a plain, readable Java program, so someone
could recover the opcode mapping by decompiling it (tracked as issue #4).
