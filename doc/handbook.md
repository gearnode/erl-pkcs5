# Introduction
This repository contains development notes about the `pkcs` library.

# Versioning
The following `pkcs` versions are available:
- `0.y.z` unstable versions.
- `x.y.z` stable versions: `pkcs` will maintain reasonable backward
  compatibility, deprecating features before removing them.
- Experimental untagged versions.

Developers who use unstable or experimental versions are responsible for
updating their application when `pkcs` is modified. Note that unstable
versions can be modified without backward compatibility at any time.

# PBKD2
Compute derived key with default derived key length:
```erlang
Iteration = 10000,
{ok, DK} = pkcs_pbkdf2:pbkdf2(sha256, <<"password">>, <<"salt">>, Iteration).
```

Compute derived key with custom derived key length:
```erlang
Iteration = 10000,
DKLen = 32,
{ok, DK} = pkcs_pbkdf2:pbkdf2(sha256, <<"password">>, <<"salt">>, Iteration, DKLen).
```
