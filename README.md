# tssc-cli-tools

Supply-chain security tools for the [tssc-validated-pattern][pattern] pipelines,
built as one Go binary in one container image.

[pattern]: https://github.com/project-lightpath/tssc-validated-pattern

## Layout

```
cmd/tssc/            single entrypoint
internal/
  cli/               subcommand wiring, flag surface, env fallbacks
  tekton/            result files, CA bundle
  version/           build metadata stamped in by the linker
tekton/tasks/        thin Task wrappers that exec the binary
```

The image also installs busybox-style symlinks, so a Task can call
`rhtpa-analyze` instead of `tssc rhtpa analyze`. See
`internal/cli/root.go:argv0Aliases`.

## Conventions

- Every flag also accepts an environment variable (e.g. `--component` /
  `COMPONENT_NAME`); flags win when both are set. The mapping is declared
  per command.
- Tekton results are written to `/tekton/results` when it exists, and
  skipped otherwise.
- Tasks in `tekton/tasks/` map params to flags and nothing else — no
  `script:` blocks.

## Development

```
make            # tidy, vet, test, build
make test       # go test ./... -race
make image      # podman build
```
