# ARM64 Go reflection tags and multiline plist

Actual hostile MiniRAT Mach-O, SHA-256 `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`.
Go 1.25.8 arm64, same source revision as go_reflection_tags_minirat.macho. Static analysis only.

Expected extracted values (file offsets):
- `0x2717e3`: 415-byte LaunchAgent plist for /bin/zsh -i
- `0x2dfab7`: `json:"iv"`
- `0x2ea4ac`: `json:"ciphertext"`

Preserves the second architecture for the shared Go reflection-tag traversal and instruction-referenced multiline-literal filtering. No additional decoder or scan pass was required.
