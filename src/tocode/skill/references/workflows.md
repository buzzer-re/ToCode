# Workflows

## Recovering source from a stripped binary (worked example)

The binary is a small network daemon, stripped. After `tocode ./netd` and
`open`:

1. **Find main and the pieces.** `xrefs` to `recv` shows one app caller,
   `sub_4012a0`; `strings` shows `"bad checksum"`, `"PING"`, `"peer %s closed"`
   used near it. `function sub_4012a0` lists its callees: `sub_401100`
   (called with the receive buffer and its length), `sub_4011c0`,
   `sub_401230`.
2. **Name by behaviour.** `decompile sub_401100`: it reads a 16-bit length at
   offset 0, a type byte at offset 2, checks a 32-bit sum at offset 4, and
   returns a pointer into the buffer or NULL: `rename sub_401100 parse_packet`.
   `sub_4011c0` switches on the type byte and calls a different function per
   value: `dispatch_packet`. `sub_401230` looks up a peer by address in a
   global array: `find_session`. `sub_4012a0` is the receive loop,
   `serve_peer`.
3. **Recover the struct.** Offsets used across those functions: 0x0 (uint16
   length, compared against the received size), 0x2 (uint8 compared against
   1, 2, 3), 0x3 (uint8 flags, masked with 0x80), 0x4 (uint32 checksum),
   0x8 (start of the payload). The type values are message kinds:

   ```c
   enum msg_type { MSG_PING = 1, MSG_DATA = 2, MSG_CLOSE = 3 };
   struct packet { uint16_t payload_len; uint8_t type; uint8_t flags; uint32_t checksum; uint8_t payload[]; };
   ```

   `declare_types` with that source.
4. **Apply types.** `set_type parse_packet "struct packet *parse_packet(uint8_t *buf, size_t len)"`,
   `set_type dispatch_packet "int dispatch_packet(struct session *peer, struct packet *pkt)"`.
   In `parse_packet`, `set_local_type` the result variable to `struct packet *`
   and `rename_local` it to `pkt`.
5. **Globals.** `rename qword_404060 g_sessions`,
   `set_type g_sessions "struct session *g_sessions"`, `rename dword_404058 g_session_count`.
6. **Sync and read.** After `sync`, `dispatch_packet` reads
   `switch (pkt->type) { case MSG_PING: ...` and the receive loop reads
   `pkt = parse_packet(buf, n);`. Repeat for `struct session` and the
   handlers until every function reads like source.

## Struct recovery checklist

- Gather every access to the pointer: the allocator's callers, functions that
  receive it, and globals that store it (`xrefs`).
- Record `offset -> size, how it is used` (compared, summed, passed to
  `strcpy`, dereferenced as a pointer, called as a function pointer).
- The allocation size (`malloc(0x28)`, `calloc(n, 0x28)`, `new` size) is the
  struct size, or an array element size.
- Fill gaps with padding (`char _pad_0x10[8];`) rather than guessing; refine
  later. Arrays show up as `base + index * size`.
- Pointers to the same struct type are list or tree links; a pointer called
  through is a function pointer (`int (*handler)(struct ctx *)`).
- After `declare_types`, set the type on the functions (`set_type`), locals
  (`set_local_type`), and globals (`set_type` on the global), then `sync`.

## Naming conventions

- Functions: verb_object (`parse_header`, `send_packet`), keep library-like
  names when the behaviour matches a known API (`memcpy`-like copy loops,
  `crc32`).
- Globals: `g_` prefix; constants and enums in UPPER_CASE.
- Keep `sub_...` for functions you have not understood yet: a wrong name
  misleads more than no name.

## Malware and firmware triage

1. `triage.json` and `imports`: networking, crypto, process injection,
   persistence (registry, services, cron), anti-debugging.
2. `strings` with filters (`http|\.exe|cmd|password|key`), then `xrefs` to
   each interesting string to find the code that uses it.
3. Constants (`search` for byte patterns, or the `eval` constant finder) to
   spot crypto (AES S-box, SHA/MD5 initial values, RC4 key scheduling).
4. Decode obfuscated strings by reading the decoder with `decompile`, then
   reproducing it in `eval` over `read_bytes` output; write the decoded
   values back as comments (`set_comment`) and `sync`.

## Folder exports (several binaries)

- `open` the folder export; each binary is a session named by its relative
  path (`bin/app`, `lib/libcrypto.so.3`), opened when first used.
- `mappings.json` at the top maps every imported symbol to the file and line
  range that defines it in another binary's export; calls in the C carry
  `/* tocode-link: name -> lib/x.so/src/raw/... */` comments.
- Work on the library side first when the executable calls into it: names
  and types recovered there make the executable's calls readable.
- `sync` on one binary also refreshes the folder's links and comments.

## When the export and the database disagree

- Edits made in the IDA or Binary Ninja UI: `sync` with `mode="full"` (or
  `tocode sync <export> --full`).
- A function missing from the export (code the analysis did not find):
  `define_function` at its address, then `sync`; it is placed next to its
  callers.
