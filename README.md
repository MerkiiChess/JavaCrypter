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

This is meant to run as the build-time half of a licensing/anti-tamper setup: you
pair it with a custom JVM that understands the substituted opcodes and ship that
JVM to your licensed users. It is **not** an antivirus-evasion tool and it does not
try to defeat someone who can attach a debugger to your custom JVM - it raises the
cost of casual decompilation, nothing more.

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

The opcode table is fixed and lives in `JarProtector.buildOpcodeTable()` - it has to
match whatever your custom JVM expects, so it's intentionally not randomized between
runs.

## Requirements

- Java 21+
- A custom JVM build that recognizes the substituted opcodes. This repo only
  produces the protected jar; the JVM side is out of scope here.

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
├── OpcodeSubstitution.java one entry in the opcode remap table
├── ClassPair.java          class + write-order priority, used to sort before writing
├── IoUtil.java             stream copy helper
└── crypt/
    ├── StringEncryptor.java   build-time AES-GCM encryption
    ├── StringDecryptor.java   embedded verbatim into every protected jar
    └── EncryptionStats.java   tracks what got encrypted, for the summary printout
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

## Notes on the string encryption

The AES key travels inside the output jar (`key.bin`, next to `StringDecryptor.class`)
so the protected app can decrypt its own strings at runtime. That's the standard
tradeoff for any client-side protection scheme - it stops someone from just grepping
the jar for strings, but the key is reachable by anyone willing to unzip the jar and
read it. The real protection is meant to come from the paired custom JVM, not from
hiding the key.
