# Introduction
This document contains development notes about the `pkcs5` library.

# Versioning
The following `pkcs5` versions are available:
- `0.y.z` unstable versions.
- `x.y.z` stable versions: `pkcs5` will maintain reasonable backward
  compatibility, deprecating features before removing them.
- Experimental untagged versions.

Developers who use unstable or experimental versions are responsible for
updating their application when `pkcs5` is modified. Note that unstable
versions can be modified without backward compatibility at any time.

# Modules
## `pkcs5_pbkdf2`
### `pbkdf2/4`
Computes a PBKDF2 (Password-Based Key Derivation Function 2) in
combination with a hash function.

Same as `pkcs5:pbkdf2(Hash, Password, Salt, InterationCount, DKLen)`.

### `pbkdf2/5`
Computes a PBKDF2 (Password-Based Key Derivation Function 2) in
combination with a hash function.

Example:
```erlang
IterationCount = 10_000,
DKLen = 32,
{ok, DK} = pkcs5:pbkdf2(sha256, <<"password">>, <<"salt">>, IterationCount, DKLen).
```

