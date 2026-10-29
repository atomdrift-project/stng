# Test fixtures

> **Warning.** Many files here are live malware: Windows, Linux and macOS
> executables taken from real intrusions. They are stored gzip-compressed so
> that nothing in a checkout is directly executable, but decompressed they
> will run. Do not run them, and handle the repository the way you would any
> other malware collection.

The fixtures total about 80 MB, so a clone is large; the crate published to
crates.io contains none of them.

## Rules

- Commit samples gzip-compressed as `name.gz`. Tests read them through
  `crate::test_fixture` (unit tests) or `tests/common` (integration tests),
  which inflate them in memory.
- Never `include_bytes!` or `include_str!` a sample.
- List every new sample below with its SHA-256 (of the uncompressed file),
  where it came from, and why it may be redistributed. A note beside a sample
  (`name.md`) can carry the detail.

## Samples

SHA-256 is of the uncompressed sample. *Not recorded* marks a sample whose
origin still has to be written down.


### elf/

Small ELF executables.

| File | SHA-256 | Origin |
|---|---|---|
| `elf/hello_linux_amd64` | `d21aef9e0e0b02408df4cd04da38466e5eaa584bef0aa9f810bfe2f3fa2c0dad` | *not recorded* |

### garble/

Go binaries obfuscated with [garble](https://github.com/burrowers/garble), and the program they were built from (`main.go`).

| File | SHA-256 | Origin |
|---|---|---|
| `garble/garble_fresh_linux_amd64` | `d1712b256c7832504ab241c497f3f32cde7b56f5ddc342be2c250178358d2ce9` | built from source in this directory |
| `garble/garble_fresh_split1` | `5151b213511c55847112e81525e8d1a7e022eb239ec704e7c73c46fdc1dedd25` | built from source in this directory |
| `garble/garble_linux_amd64_1` | `bd3c49d1ffa19bda0949c7460378f9fdf0d870cfda0200550cd630daef6d4cee` | built from source in this directory |
| `garble/garble_linux_amd64_10` | `433a4a04b12ae556fe7593dd1095f95a5a8dabb74377e58ea75319e4eb9cb417` | built from source in this directory |
| `garble/garble_linux_amd64_11` | `fa996fc43f8eed60db717409f0fe3d91e5f5aef03a08688f7da101623570bfbb` | built from source in this directory |
| `garble/garble_linux_amd64_12` | `fa6f0b722d0e3568279a4b6168273c0c0e211debb0f4328e17344b25af29e9de` | built from source in this directory |
| `garble/garble_linux_amd64_13` | `f8723f8772b63d599f5985cb523233ed87141c981c13be8ca6fa39d3a3a8f597` | built from source in this directory |
| `garble/garble_linux_amd64_14` | `8a5212e969e9764c70dffb6271553f6b76d813d66bc6d6c65c61ca30cb3a3633` | built from source in this directory |
| `garble/garble_linux_amd64_15` | `69580c68ac42285ab1f990a0d5f8b283a12456ea7bc3dcd77c7d0f7e42172154` | built from source in this directory |
| `garble/garble_linux_amd64_16` | `fe2e903436b41b8eca790dc66ac1c6fbe9d85fa80f5f466d8ff800608e130439` | built from source in this directory |
| `garble/garble_linux_amd64_17` | `fa6366c3b479de68a71870773330bb767b19e862f313e13485f6cb95a59ef8b5` | built from source in this directory |
| `garble/garble_linux_amd64_18` | `6116d484f7e451e75d2b4d640218a87bbf35205492fa7d8c85229e18658395b7` | built from source in this directory |
| `garble/garble_linux_amd64_19` | `f280e9e538c5f7b726ff0c4dced7e0f4d6c74e7705904e85f31bbc728a222746` | built from source in this directory |
| `garble/garble_linux_amd64_2` | `dc42de5914f577c8f2bfd512b491704baf1b8742dec9342f81b176a2f9dde5a6` | built from source in this directory |
| `garble/garble_linux_amd64_20` | `b7ba6d29c38723b4040c96f31e93cbe89367c8f2fed441c766eb66eaac13cabb` | built from source in this directory |
| `garble/garble_linux_amd64_3` | `f9dee9deaccda69effd244a4ac815a3e3dffb52bfee7ddc70e3d4a2c9405e870` | built from source in this directory |
| `garble/garble_linux_amd64_4` | `82cf01b26285446f960697ba5b4fe036a80e0b8784c2e94ae77f17ad6e039b96` | built from source in this directory |
| `garble/garble_linux_amd64_5` | `ccb0714ffce6d39c5f5774146160fdf2f1c91a6a7faa40fc1d02c3e8dcd42211` | built from source in this directory |
| `garble/garble_linux_amd64_6` | `c513568dffe7b039ef8450d5050adca6a514ad5b752b05f35972087138855a44` | built from source in this directory |
| `garble/garble_linux_amd64_7` | `e8079f28d769e1c7f8bd7c5c76fc7cc899df47c3d7ed65d6a310a99dfdb9e0a4` | built from source in this directory |
| `garble/garble_linux_amd64_8` | `34fbc7eebbd4f1ae5286df372105f02eb523ec922f5cbefc4151062e4b759371` | built from source in this directory |
| `garble/garble_linux_amd64_9` | `fdf5f6de692a55cda7344aad0ef0feaf0af2c48ed9adfc9d181f00dfbb4316af` | built from source in this directory |
| `garble/garble_seed_1` | `ae7cc673e0285311a8fa43048f8862c015451dd47f53634c8d43439ee69d2a83` | built from source in this directory |
| `garble/garble_seed_10` | `bcca134b08c7baa62e8b059c2eaca532ea0c1dc933e1af621d256c2ba2b15fc4` | built from source in this directory |
| `garble/garble_seed_2` | `5da0e95bd26bb880bffdafeb024a06f9e2030dd287b452f41bc07e925980e816` | built from source in this directory |
| `garble/garble_seed_3` | `6cd507bfc178a340b647eda7a9af7eb8f84ad83872929dd9991795e5562ff2ed` | built from source in this directory |
| `garble/garble_seed_4` | `2c21584fe4f2a6664168e4cfd24ae36f5ac831c43b80f3f95d0a6e0bdc8c1180` | built from source in this directory |
| `garble/garble_seed_5` | `98b7e11ec008ae9be61f9cd175a4f7c7e054c380be91a7521d36f5b13e32d946` | built from source in this directory |
| `garble/garble_seed_6` | `3d2e13b9965fa0c38f696ba44837ca6f9824e475dfc3b8783f00160dbe295445` | built from source in this directory |
| `garble/garble_seed_7` | `117b9f03ab75b78c2920caf63dfa0d98cf0ce64f1a63bfffa0a3b79c27d9c24a` | built from source in this directory |
| `garble/garble_seed_8` | `a391c7cd328bcc2e576e6a7f7a8add63d9909ee639da04b66eaae32c09af13c5` | built from source in this directory |
| `garble/garble_seed_9` | `a6144d12b67250e22f5aa7ee91a04b6434df50e7db3361c39b2b494387b71ceb` | built from source in this directory |
| `garble/garble_simple_only` | `6578e95d97f8b1046d3d09e978865b73ea91bb0bb893b60b50182459636d3626` | built from source in this directory |
| `garble/garble_simple_test` | `88bf27ba0ad973d888ebae833fea28c1c7ccb8a30e3106fdb581824996f20bf4` | built from source in this directory |

### go_pclntab/

One Go program built stripped for six targets; see [go_pclntab/README.md](go_pclntab/README.md).

| File | SHA-256 | Origin |
|---|---|---|
| `go_pclntab/darwin_amd64` | `54d4a4cd26f7543695787eb381ed65d6cafd8bd64d665f45b498d46d9bc37da7` | [README.md](go_pclntab/README.md) |
| `go_pclntab/darwin_arm64` | `bda259ce427bea82e8259804a834197979d229aa627aabc0092407bdf5babd16` | [README.md](go_pclntab/README.md) |
| `go_pclntab/linux_amd64` | `9c309ec06f83a79ce38f55440fe7c43a64fe048626ff08ea18f9956d00011282` | [README.md](go_pclntab/README.md) |
| `go_pclntab/linux_arm64` | `92061f225fb10be62b0dc746cc422889b70493746e1a874958d58c4b7c4ae59d` | [README.md](go_pclntab/README.md) |
| `go_pclntab/windows_amd64` | `55ccb5c593d8b26dcef124ecc48270a01507932a772d70a6c1fdefd8e8ce8000` | [README.md](go_pclntab/README.md) |
| `go_pclntab/windows_arm64` | `fa4f310e3a21f049b13c2c3ab58bf2ba25a0c8d444f475f03de6fb28955b1a45` | [README.md](go_pclntab/README.md) |

### kworker_samples/

`kworker` process-spoofing malware; see [kworker_samples/README.md](kworker_samples/README.md).

| File | SHA-256 | Origin |
|---|---|---|
| `kworker_samples/kworker_obfuscated_1` | `caa69b10b0bfca561dec90cbd1132b6dcb2c8a44d76a272a0b70b5c64776ff6c` | [README.md](kworker_samples/README.md) |

### macho/

Mach-O executables, thin and universal, most of them macOS malware.

| File | SHA-256 | Origin |
|---|---|---|
| `macho/arm64_lcg_xor_universal.macho` | `a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1` | [arm64_lcg_xor_universal.md](macho/arm64_lcg_xor_universal.md) |
| `macho/charge0x_installer_universal.macho` | `8202c3887b75b107f76385fe36e7949860b7931cebd2c65899649556c37e30bc` | *not recorded* |
| `macho/fmix_xor_stealer_universal.macho` | `bfc96a7fa7aaf817b083b72d71f58c3b962d3192ae6f79b6abda9911d73b1ea9` | [fmix_xor_stealer_universal.md](macho/fmix_xor_stealer_universal.md) |
| `macho/go_reflection_tags_minirat.macho` | `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d` | [go_reflection_tags_minirat.md](macho/go_reflection_tags_minirat.md) |
| `macho/go_reflection_tags_minirat_arm64.macho` | `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270` | [go_reflection_tags_minirat_arm64.md](macho/go_reflection_tags_minirat_arm64.md) |
| `macho/rust_arm64_framed_register_writes.bin` | `9ee6da6ea93282f4d33dace64dad2ad847ca7a41954e121b853c98e5c6ff7bb8` | [rust_arm64_framed_register_writes.md](macho/rust_arm64_framed_register_writes.md) |
| `macho/rust_arm64_register_writes.bin` | `6ab047751369f7ff63c16dfcb684ced5c28f77da63f5d02e9264e9cbc2e4f1bd` | [rust_arm64_register_writes.md](macho/rust_arm64_register_writes.md) |
| `macho/rust_heap_xor_installer_universal.macho` | `78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970` | [rust_heap_xor_installer_universal.md](macho/rust_heap_xor_installer_universal.md) |
| `macho/swift_small_strings_webview.macho` | `e804a52fe033d7e99f4e51c5b7f70bd5101e61de1478f5c619219fea8ef8a957` | [swift_small_strings_webview.md](macho/swift_small_strings_webview.md) |
| `macho/wallet_report_objc` | `19a2398bb4ff5cd4d7ab1a822fedf2ac379d09b0abce5606b80e5c736a9887ff` | *not recorded* |
| `macho/xor_fat_dropper.macho` | `30c99015f9c432604d8a8206ce8dcb4fba7866b062e5bd1a8f0adb88fba8807c` | [xor_fat_dropper.md](macho/xor_fat_dropper.md) |

### malware/

Live malware from several families and platforms.

| File | SHA-256 | Origin |
|---|---|---|
| `malware/brew_agent` | `545dd5cba264bf242bc837330ca34247e202f7ac25f03eec63bf5842357519f1` | *not recorded* |
| `malware/brickstorm_linux_amd64` | `320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759` | *not recorded* |
| `malware/dynamichub/DynamicHub` | `bf7b6aba8f04f7b84949a343e2d333f5e9ee80552133ada688ce6eb06a514117` | *not recorded* |
| `malware/goodboy-stage-01.exe` | `c2b32f6d7e706e143055a38ce5caee0bddc9524b28e560100dc0ed4369aa27f4` | *not recorded* |
| `malware/kimwolf_installer` | `79569c91433c6e263cf48c8129023e5b5678fee5bdbdcb9a8075a412affabbe2` | *not recorded* |
| `malware/poolrat` | `85045d9898d28c9cdc4ed0ca5d76eceb457d741c5ca84bb753dde1bea980b516` | *not recorded* |
| `malware/sample-stealer` | `bc345e168282f5c63eacd284bf1419f9c9897bce2445672a75232d092692856d` | *not recorded* |
| `malware/sorry_ransomware.exe` | `42a1aded85892a80c83f741a7ac00e7e75015166c3be0bae29d93d3a4714711d` | *not recorded* |
| `malware/themeforestrat` | `ff32bc1c756d560d8a9815db458f438d63b1dcb7e9930ef5b8639a55fa7762c9` | *not recorded* |
| `malware/threadracer.exe` | `1533ea9aeeb2790b2fcf0629d9e9f9ad531000f2072c8e4e2077d461de15a3eb` | *not recorded* |
| `malware/vget_sample` | `0da5a7d302ca5bc15341f9350a130ce46e18b7f06ca0ecf4a1c37b4029667dbb` | *not recorded* |
| `malware/wizardnet_downloader.dll` | `7f947fc58357179a575e4f2521422dbd7b9eed6e1def1ff640c5002a413cc151` | *not recorded* |
| `malware/zyravpn_tun2socks.exe` | `90547fe071fe471b02da83dd150b5db7ce02454797e7f288d489b1ff0c4dd67c` | *not recorded* |

### nsis/

NSIS installer payloads.

| File | SHA-256 | Origin |
|---|---|---|
| `nsis/4d49_Constraining.Opm` | `ffd358064cf00d483d606dc81088c59bb06b6a86a0de5b6076272977903711ec` | *not recorded* |
| `nsis/57527_Hokerer118.hex` | `4cdc88e916fd12037f14c7d4a0d8d35cbd3cb86eb1d3e5a92f15b1ea04f5a1a1` | *not recorded* |

### pe/

Windows PE executables and DLLs, benign and .NET.

| File | SHA-256 | Origin |
|---|---|---|
| `pe/does-nothing-windows-amd64.exe` | `690dffe97a943cec1569228e658dc6a1ed05d6a1b0884f35e5c29a8c0c1b58a2` | *not recorded* |
| `pe/dotnet_unsigned_x86.dll` | `12e477ab6a025ca701babb7ff902d485ad83f6b59aeff1fb838ece5eecd04202` | *not recorded* |
| `pe/gobump_windows_amd64.exe` | `ba49bd5dcee14aa5d197901fc8f0c99515f8f069ae14e8f479b38540d18bc509` | *not recorded* |
| `pe/hello_windows.exe` | `018628e34108c5d6dfe9e8a633120a90313f8fffd7a15feacc361cd5fc2088e0` | *not recorded* |
| `pe/msvc_console_amd64.exe` | `bc457d403feeab416d25aebaecf35b7d91aa9675a587eefe6ed237de290d5718` | *not recorded* |
| `pe/rtc.dll` | `4332c52e01571bbb1a1903661b31822e0ccca164cc1789b1ecb86eeaf245231c` | *not recorded* |

### rust_elf/

A Rust program built stripped; see [rust_elf/README.md](rust_elf/README.md).

| File | SHA-256 | Origin |
|---|---|---|
| `rust_elf/linux_amd64` | `e3659a9d5f69bb37cbe65eb13738a767b893c6886e3fb31cc5d3a4d8320940bf` | [README.md](rust_elf/README.md) |

### script/

Obfuscated scripts: batch, JavaScript, VBScript-encoded ASP.

| File | SHA-256 | Origin |
|---|---|---|
| `script/batch-cp708-powershell-dropper-db9.bat` | `db9c0fd3a144ea0a24d8d65841ae94f7336ed420428dd455ed4b27ac081949c5` | *not recorded* |
| `script/batch-cp708-powershell-dropper-e289.bat` | `e289984a016e8c115d118ec46bb7b29fcc68242a73ff034e17374b0f6f8adbcb` | *not recorded* |
| `script/batch-remap-sample.unknown` | `7aa213b2d52af66af4deb6787385da1ff023d6ba2e39bfe0824eaf3436806797` | *not recorded* |
| `script/jso-inert-permutation.js` | `354340394f92cca946229ba4bac7e2d057a24994e7e4c1bf65164abbbda9132c` | *not recorded* |
| `script/jso-permutation.js` | `c6a9028513792f288fec1d7c217c55d9541d96d436cb119ef0553c3fd49d6c41` | *not recorded* |
| `script/npm-charcode-rot-packer.js` | `14a481492dbdcc653d4bdc714ddfcc4858427f094fe559a9ca73b241c8c25d1a` | [npm-charcode-rot-packer.md](script/npm-charcode-rot-packer.md) |
| `script/vbscript-encode.asp` | `8f23f05d5f97707f4e3e4d90175a099fb924b07c9ed7b81e3a1b8d4bc1c471df` | *not recorded* |
| `script/vbscript-encoded-malformed-asp.asp` | `b8245c841a661992e8e68462b66c3f27115c892fbe929de0b73ccc2c83e63456` | *not recorded* |

### xor/

XOR-obfuscated payloads and regions.

| File | SHA-256 | Origin |
|---|---|---|
| `xor/brew_agent_xor_region.bin` | `a0f509a4d46040107a8a2355d3f7734d3f71efdea50d8e9384f996d09333aa69` | [brew_agent_xor_region.md](xor/brew_agent_xor_region.md) |
| `xor/brew_agent_xor_sample` | `545dd5cba264bf242bc837330ca34247e202f7ac25f03eec63bf5842357519f1` | *not recorded* |
| `xor/libffmpeg_3cx_x64_xor` | `87c5d0c93b80acf61d24e7aaf0faae231ab507ca45483ad3d441b5d1acebc43c` | *not recorded* |
| `xor/overlay_crypter_loader_xor` | `a3c64998a58595b7a6c2d16db68a767a87c9f3c3eb89784870ce51667a09d15b` | [overlay_crypter_loader_xor.md](xor/overlay_crypter_loader_xor.md) |
