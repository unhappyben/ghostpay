# vendor/

Third-party browser modules, vendored so the app makes zero CDN requests at runtime.
Every file carries a provenance header; the table below records source URL, version and
the sha256 of the vendored file as committed (headers included), so integrity can be
re-checked with `shasum -a 256 <file>`.

| file | package | version | source URL | sha256 |
|---|---|---|---|---|
| noble-curves-secp256k1.mjs | @noble/curves (`/secp256k1.js`) | 1.6.0 | https://esm.sh/@noble/curves@1.6.0/es2022/secp256k1.bundle.mjs | e1b058cd4de6f2db4546c98dc841a5728586a6e5a45af2a9e749e45d839c8e1a |
| noble-hashes-sha256.mjs | @noble/hashes (`/sha256.js`) | 1.5.0 | https://esm.sh/@noble/hashes@1.5.0/es2022/sha256.bundle.mjs | 8722a53320703670f23163dccd11da7ca1a8fdd0ca7667d671c8230ca18fbf20 |
| noble-hashes-sha3.mjs | @noble/hashes (`/sha3.js`) | 1.5.0 | https://esm.sh/@noble/hashes@1.5.0/es2022/sha3.bundle.mjs | be4fe761bc9cba36a75f40239bb736948841575804597e9b4c4a041b365985e7 |
| ethers.mjs | ethers | 6.13.4 | https://esm.sh/ethers@6.13.4/es2022/ethers.bundle.mjs | 8b361747afe2a0981531e2bbe1e9dcf2d381da6c9b686f7e7c9d8083da6a71c5 |
| qrcode-generator.mjs | qrcode-generator | 1.4.4 | https://esm.sh/qrcode-generator@1.4.4/es2022/qrcode-generator.bundle.mjs | 20fd2693cd81a693f075ba5da91e225f0f3453709740aa7c15c594a558911a14 |
| latrine-irn.mjs | @hazae41/latrine (`/out/mods/irn/mod.js`) | 2.1.7 | https://esm.sh/@hazae41/latrine@2.1.7/es2022/out/mods/irn/mod.bundle.mjs | d4a7bb9a9d03c2331fe68c0292600f131add88be001092a427ec690a2fe74eea |
| latrine-wc.mjs | @hazae41/latrine (`/out/mods/wc/mod.js`) | 2.1.7 | https://esm.sh/@hazae41/latrine@2.1.7/es2022/out/mods/wc/mod.bundle.mjs | e7330ccff448418f3b0821c7adfd103b756e8b313934da7cb8e2b2c85f4d6889 |
| latrine-jwt.mjs | @hazae41/latrine (`/out/libs/jwt/mod.js`) | 2.1.7 | https://esm.sh/@hazae41/latrine@2.1.7/es2022/out/libs/jwt/mod.bundle.mjs | 4640fc9a185fcd386085f9d85ff46afe20bff829c9c0c0b952ef3e1d768689cc |
| snarkjs.mjs | snarkjs | 0.7.5 | https://esm.sh/snarkjs@0.7.5/es2022/snarkjs.bundle.mjs | 11c41ad76cc49939eacdcf4f790f39a0e23af8fd9a1a8e2691f829bc10da650b |
| esm-node/process.mjs | esm.sh node polyfill (unenv) | node 22.14.0 API | https://esm.sh/node/process.mjs | 58054b235c6a6bb2f6f95f48ab6fb9b7a9aff211579105de6acf4a6a207581b3 |
| esm-node/events.mjs | esm.sh node polyfill (unenv) | node 22.14.0 API | https://esm.sh/node/events.mjs | 753243e43e74d065f1b102d7d1a1545221b02c21077345134521a165337ca924 |
| esm-node/tty.mjs | esm.sh node polyfill (unenv) | node 22.14.0 API | https://esm.sh/node/tty.mjs | 56e7b71e33450a0d4f389d73ea55ecfae542db73342c161b49e2dde4bfb48f3d |
| esm-node/async_hooks.mjs | esm.sh node polyfill (unenv) | node 22.14.0 API | https://esm.sh/node/async_hooks.mjs | 1dc603ac23961b4f4d6de694e2e27e735c0f049bf5fa066ba05627ea7ede030f |

Notes:

- The esm.sh bundles are the `es2022` target with dependencies inlined (the `?bundle`
  build). Each is self-contained; snarkjs.mjs alone needed the node process polyfill,
  which lives under esm-node/ with its imports rewritten to relative paths.
- @hazae41/latrine was previously imported unpinned; 2.1.7 is what esm.sh resolved to
  at vendor time and is now the pinned version.
- poseidon2.mjs / poseidon13.mjs / tc-pedersen.mjs predate this README: hand-ported,
  with provenance in their file headers (poseidon-lite@0.3.0 and circomlibjs@0.1.7).
