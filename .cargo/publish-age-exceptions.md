# Publish-age exceptions

Cargo 1.100 does not support package-specific publish-age exceptions. A recent
version already recorded in `Cargo.lock` is permitted even while
`resolver.incompatible-publish-age = "deny"` is active. The entries below
preserve the exceptions previously reviewed for this repository.

To intentionally admit one of these versions into the lockfile, use a narrowly
targeted update while temporarily allowing recent versions:

```sh
cargo update -p <crate> --precise <version> --config 'resolver.incompatible-publish-age="allow"'
```

Review the complete `Cargo.lock` diff before committing it. The temporary
`allow` setting applies to the whole resolution operation, including transitive
dependencies. Normal builds and CI should continue using `--locked`.

If `Cargo.lock` is deleted, these documented exceptions are not applied
automatically and must be reviewed and admitted again.

## Previously reviewed exceptions

```toml
[[allow.exact]]
crate = "chacha20"
version = "0.10.2"
```
