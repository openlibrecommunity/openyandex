# dev

- c, go, ts bun dev
- kiss, minimal, no bloat, no verbose code
- no em-dashes (-), only hyphens (-)
- short descriptions, abbreviate everything like "enc/dec", "c n go dev, s fun"
- 0BSD license
- master branch, not main
- git commits: author nori <sexygirl31337@gmail.com>, short lowercase messages, no period
- first commits in repo: epoch date (1970-01-01) + author sexygirl31337@gmail.com for anon init
- github for hosting (github.com/neuronori), gh-ci
- golangci-lint v2 strict, 0 issues always
- pure go, zero external deps where possible
- performance matters: benchmark, profile, optimize hot paths
- readme.txt, not readme.md
- fish shell, arch linux
- eza for ls, starship prompt
- gh cli for github
- work in a vm
- user : zaraza
- pass : zaraza
- sudo : zaraza

# code style

- package comments required
- no globals without nolint + reason
- functions under 60 statements
- cyclomatic complexity under 15
- test with -race flag
- pre-allocate buffers, reuse memory
- early return, no deep nesting
- errors: sentinel exported, wrap with context

# project patterns

- def go structure
- tests next to code (_test.go)
- CI: test -race + lint in gh-ci
- disable PRs, wiki, projects on repos - only issues + actions
- github API via gh-cli or curl
- gpg key - 673BDF5C072AEC85
- ssh key - id_ed25519

# deps and tools

- golangci-lint latest (v2.12+)
- go install for tooling, ~/.go/bin in PATH
- ~/.local/bin for local binaries
- go version 26

# communication

- direct, no filler, no "absolutely", no "great question"
- if stuck twice - change approach completely, don't patch incrementally
- admit when wrong, don't bullshit
- russian language preferred for discussion
- english for code and comments
