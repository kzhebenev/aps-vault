# KDBX test vectors

| file | origin | opens with | format |
|---|---|---|---|
| `Format300.kdbx` | KeePassXC `tests/data` (GPL-3 test data, used as vectors only) | password `a` | KDBX 3.0, AES-KDF, AES-256 |
| `NewDatabase.kdbx` | KeePassXC `tests/data` | password `a` | KDBX 3.1, AES-KDF, AES-256, Salsa20 inner stream |
| `Format400.kdbx` | KeePassXC `tests/data` | password `t` | KDBX 4.0, Argon2d, ChaCha20 |
| `FileKeyXmlV2.kdbx` + `.keyx` | KeePassXC `tests/data` | key file only (v2 XML with hash) | KDBX 3.1 |
| `FileKeyXmlV2HashFail.kdbx` + `.keyx` | KeePassXC `tests/data` | must be refused: the key file's hash does not match | — |
| `kdbx4-argon2d-aes.kdbx` | written by pykeepass 4.2.0 | password `pw-1` | KDBX 4.0, Argon2d, AES-256, ChaCha20 inner stream; a history entry with a protected value |
| `kdbx4-argon2id-chacha20.kdbx` | pykeepass 4.2.0 | password `pw-1` | KDBX 4.0, Argon2id, ChaCha20 |
| `kdbx4-pw-and-keyfile.kdbx` + `FileKeyBinary.key` | pykeepass 4.2.0 | password `pw-1` + 32-byte binary key file | KDBX 4.0 |
