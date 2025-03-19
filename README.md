# auditd-parser


# TODOs
- [ ] Add tests
  - [ ] parse_record unit tests
  - [ ] Parser integration tests
    - Add a test for SYSTEM_SHUTDOWN logs, see https://github.com/linux-audit/audit-kernel/issues/169
  - [ ] Fuzz testing?
- [ ] justfile to run CI
- [ ] Clippy pedantic lints
- [ ] Add CI
- [ ] Add release workflow with `release-plz` crate
- [ ] Add documentation
- [ ] CLI binary to read auditd logs? Or at least, as an example of how to use the library

# MSRV
`rustc 1.85`
