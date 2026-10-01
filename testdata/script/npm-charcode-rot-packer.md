# npm-charcode-rot-packer.js

A trimmed capture of the packer used by the compromised `awaitly-*` / `autotel-*`
npm releases (`compromised_lib/awaitly-libsql/22.0.1` and siblings). The
original `package/index.js` is 4.5 MB; this keeps the authentic wrapper and
enough of the payload to reach the AES staging call.

The recipe is three layers deep:

  [char codes].map(c => String.fromCharCode(c)).join("")   ->  rotated text
  Caesar shift of 6                                        ->  JavaScript
  eval                                                     ->  stage 2

Stage 2 then AES-128-GCM-decrypts further blobs with a hardcoded key, and one of
those downloads the Bun runtime and runs the real payload outside Node.

It is a regression fixture for two things that both had to be true for any of it
to be visible: the array spelling of the charcode recipe (the direct
`eval(String.fromCharCode(...))` matcher does not see it), and recovering the
shift rather than assuming ROT13.
