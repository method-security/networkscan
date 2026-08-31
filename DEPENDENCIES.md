# Dependency security posture

Last reviewed: **2026-08-31**. Tooling: `govulncheck -mode=source ./...` and
`osv-scanner --lockfile=go.mod`.

Reachable-vulnerability count at last review: **3**, all of which have **no
published fix**. Everything with a fix available has been taken.

Reproduce with:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck -mode=source ./...
```

`govulncheck` is the number that matters here — it does call-graph reachability,
so it distinguishes "this module is in our graph" from "our code can actually
reach the vulnerable function". `osv-scanner` reads `go.mod` and reports the
former, which is a much larger and much noisier set. Where the two disagree,
prefer `govulncheck`, and record the reasoning rather than just the verdict.

## Accepted risk

These are known, adjudicated, and deliberately not fixed. Do not "fix" one
without reading the reasoning and re-adjudicating.

| ID | Module | Why accepted |
|---|---|---|
### GO-2026-5932 — `golang.org/x/crypto`

**Not an exploitable defect.** Read the advisory text: *"the golang.org/x/crypto/openpgp
package is unmaintained, unsafe by design, and has known security issues."* It is a
blanket **deprecation notice** for the package, which is why `Fixed in: N/A` — there is no
patch, the remedy is "stop using it". Do not triage this as if it were a CVE.

It reaches us through `google/go-github/v30` (a 2020-era release), which
`projectdiscovery/utils` uses for verifying self-update release signatures:

```
internal/discover/port → naabu runner → projectdiscovery/utils/update
                       → go-github/v30 → x/crypto/openpgp/armor
```

Three reasons it is accepted:

1. It is a deprecation advisory, not an exploitable bug.
2. The code path is dead — `utils/nuclei/runner/runner.go` calls
   `nucleilib.DisableUpdateCheck()`, so the signature verification it exists to serve
   never executes.
3. It cannot be removed. go-github v30 is pinned by `projectdiscovery/utils` and we are
   already on that module's current release. Excising it means a `replace` directive that
   breaks `utils`.

Unlike the docker entries below, this package **is** compiled in (~140 symbols). Its
presence is not in dispute; its exploitability is.

### GO-2026-4887 and GO-2026-4883 — `github.com/docker/docker`

Both are **Moby daemon-side** issues: an AuthZ plugin bypass on oversized request bodies,
and an off-by-one in plugin privilege validation. networkscan is a CLI scanner, not a
Docker daemon.

This is not an assertion — it was verified against the built binary:

```sh
go build -mod=vendor -o /tmp/networkscan .
go tool nm /tmp/networkscan | grep -cE 'docker/docker/(daemon|pkg/authorization)'
# => 0
```

Only `docker/docker/api/types/...` (data structs) and `docker/docker/client` are linked.
The packages containing the vulnerable code are **not in the binary at all**. govulncheck
reports these via `init()` reachability, which is its weakest signal: the package
initialiser runs, the affected functions are not present to call.

They arrive because `utils/nuclei/report` imports `nuclei/v3/lib`, nuclei's SDK entry
point, which reaches `pkg/protocols/code → gozero/sandbox → docker/api/types/container`.
This is not trimmable: `NucleiEngine` is defined in `lib`, so importing sub-packages
instead would mean reimplementing template execution; and `gozero/sandbox`'s
`virtual_env_docker.go` carries no build tag, so it compiles on every platform. Taking
nuclei 3.8.0 also removed `go-pg/pg` v8, an unmaintained module whose advisory had no fix
and never would.

## Deliberate version holds

Two dependencies are pinned below their latest release. Both have the full
reasoning inline in `go.mod` at the require line, which is where you will trip
over them — read that before changing either.

| Module | Held at | Reason (short) |
|---|---|---|
| `github.com/projectdiscovery/naabu/v2` | v2.3.3 | Product decision, predates this sweep. **Not a security hold.** See the go.mod comment for the nuclei shared-graph trap. |
| `github.com/getkin/kin-openapi` | v0.132.0 | Incompatible API change; nuclei does not compile against it. All its advisories are in `openapi3filter`, which is not imported. Pulls `oasdiff/yaml` and `oasdiff/yaml3` along with it. |

There is **no middle version** for kin-openapi, which is worth knowing before someone
spends an afternoon looking for one. The API break (`Schema.ExclusiveMin` changing from
`bool` to `ExclusiveBound`) is already present at v0.140.0, and the earliest version that
fixes any advisory is v0.141.0. Every version that would silence any part of a scanner
already contains the break that stops nuclei compiling.

Both holds are enforced by `dependency_guard_test.go`, not just documented. The naabu
guard asserts the pinned version; the kin-openapi guard asserts `openapi3filter` is absent
from the vendor tree, which is proof of non-import because `go mod vendor` vendors exactly
the packages in the import graph.

## Before you bump anything

This repo has almost no unit-test coverage of dependency behaviour — 24
hand-written test functions, none of which touch a third-party surface. A green
`go build` is **not** evidence that a bump is safe.

Run the smoke test, which drives the real CLI against real local listeners:

```sh
scripts/smoke/smoke.sh
```

Run it once **before** your change and once after, and compare. A suite that
only passes after the change tells you nothing; the before-run is the control.

Section 2 of that script is the naabu check and is the one that matters most —
naabu is pinned, but bumping nuclei moves naabu's shared transitive graph
underneath the pin, so "naabu is still v2.3.3" is not evidence it still scans.

**This script is not wired into CI.** That is a deliberate choice, and it has a
consequence worth stating plainly: the only protection against shared-graph
drift is a person remembering to run it. `dependency_guard_test.go` catches a
naabu *version* change automatically, but nothing catches naabu's dependencies
moving underneath the pin except this script, run by hand. If dependency work
starts happening more often, wiring it into `verify.yml` is the obvious next
step — it needs only python3, openssl and `libpcap-dev`, all of which the
verify job already has.
