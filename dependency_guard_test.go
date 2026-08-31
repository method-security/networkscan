package main

// Guards for two deliberate dependency decisions that are otherwise only
// described in prose in go.mod. A comment records an intention; these tests
// defend it.
//
// Both are cheap, hermetic, and read files already in the repo -- they add no
// build or network dependencies and run inside `./godelw verify`.

import (
	// Standard
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// naabuPin is the version github.com/projectdiscovery/naabu/v2 is locked to.
// If you are changing this constant, you are almost certainly doing something
// you should not be -- read the block comment on the naabu require line in
// go.mod first.
const naabuPin = "v2.3.3"

// TestNaabuStaysPinned fails if naabu moves off its locked version.
//
// naabu is pinned for product reasons that predate the 2026-08 dependency
// sweep. This catches the obvious mistake -- someone running `go get -u` or
// bumping it to clear a scanner finding.
//
// LIMIT OF THIS TEST, and it is an important one: this only checks the version
// string. It does NOT detect the failure mode that actually matters, which is
// naabu's shared transitive graph (projectdiscovery/utils, fastdialer,
// retryablehttp-go, mapcidr, gologger) moving underneath the pin when nuclei is
// bumped. That is invisible in go.mod by construction. Only a real scan
// catches it -- run scripts/smoke/smoke.sh, whose section 2 asserts a CONNECT
// scan finds the open ports and rejects a closed control port. Run it before
// and after your change; the before-run is the control.
func TestNaabuStaysPinned(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	re := regexp.MustCompile(`(?m)^\s*github\.com/projectdiscovery/naabu/v2\s+(\S+)`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatal("could not find a github.com/projectdiscovery/naabu/v2 require line in go.mod")
	}

	if got := string(m[1]); got != naabuPin {
		t.Fatalf(`naabu is pinned at %s but go.mod now says %s.

naabu is LOCKED. If this bump is deliberate, the person who owns port-scanning
behaviour needs to sign off, and you must re-run scripts/smoke/smoke.sh (the
port-scan assertions in section 2) before and after. See the block comment on
the naabu require line in go.mod for why the pin alone is not sufficient
protection.`, naabuPin, got)
	}
}

// TestOpenAPIFilterNotImported fails if anything starts importing
// kin-openapi's openapi3filter package.
//
// kin-openapi is held at v0.132.0 because every version that fixes its
// advisories (v0.141.0 and up) contains an API change that nuclei does not
// compile against. That hold is safe ONLY because all four of those
// advisories -- including GHSA-r277-6w6q-xmqw, a fail-open authentication
// bypass rated CRITICAL -- live in openapi3filter, the server-side
// request-validation package, which nothing here imports. nuclei uses the
// openapi3 spec parser only.
//
// This test makes that premise enforceable rather than merely documented. If
// someone adds OpenAPI request validation, the hold silently stops being safe
// and we become genuinely exposed to a fail-open auth bypass. This fails the
// build at that moment and says why.
//
// It works because `go mod vendor` vendors exactly the packages in the import
// graph and no others, so the directory's absence is proof of non-import.
func TestOpenAPIFilterNotImported(t *testing.T) {
	dir := filepath.Join("vendor", "github.com", "getkin", "kin-openapi", "openapi3filter")

	// Sanity-check the mechanism before trusting its verdict: if the sibling
	// openapi3 package is missing too, we are not in a vendored tree and this
	// test would pass vacuously.
	sibling := filepath.Join("vendor", "github.com", "getkin", "kin-openapi", "openapi3")
	if _, err := os.Stat(sibling); err != nil {
		t.Skipf("vendor tree not populated (%s missing); nothing to assert", sibling)
	}

	if _, err := os.Stat(dir); err == nil {
		t.Fatalf(`%s is now vendored, which means something imports openapi3filter.

kin-openapi is held at v0.132.0 and that hold is only safe while openapi3filter
is unused -- all of its advisories, including a CRITICAL fail-open auth bypass,
are in that package. If this import is intentional, the hold must be revisited:
either nuclei has to move past kin-openapi v0.144.0, or the validation code
needs to go. Do not simply delete this test. See the block comment on the
kin-openapi require line in go.mod.`, dir)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", dir, err)
	}
}
