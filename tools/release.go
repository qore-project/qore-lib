//go:build ignore

// Release preflight checks module metadata, and optionally a release tag.
//
// From the repository root:
//
//	GOWORK=off GOPROXY=off GOTOOLCHAIN=local go run ./tools/release.go -version v0.1.0 -check
//
// -check validates only the version; without it, go.mod is also checked.
// Omitting -version checks only go.mod, as used by standalone CI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const modulePath = "github.com/qore-project/qore-lib"

var versionPattern = regexp.MustCompile(`^v(0|1)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func main() {
	version := flag.String("version", "", "release tag to validate; omit to check only go.mod")
	check := flag.Bool("check", false, "check only -version, without reading module metadata")
	flag.Parse()

	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"))
	}
	if *check && *version == "" {
		fail(fmt.Errorf("-check requires -version"))
	}
	if *version != "" {
		if err := validateVersion(*version); err != nil {
			fail(err)
		}
	}
	if !*check {
		if err := validateModule(); err != nil {
			fail(err)
		}
		fmt.Printf("module %s has no local replacements\n", modulePath)
	}
	if *version != "" {
		fmt.Printf("release tag %s is valid\n", *version)
	}
}

func validateVersion(version string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("invalid release tag %q: use canonical v0.x.y or v1.x.y, optionally with a prerelease and without build metadata", version)
	}
	if version == "v0.0.0" {
		return fmt.Errorf("v0.0.0 is reserved for the unpublished development snapshot")
	}
	_, prerelease, ok := strings.Cut(version, "-")
	if !ok {
		return nil
	}
	for _, label := range strings.Split(prerelease, ".") {
		if len(label) < 2 || label[0] != '0' {
			continue
		}
		numeric := true
		for i := range len(label) {
			if label[i] < '0' || label[i] > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			return fmt.Errorf("invalid release tag %q: numeric prerelease labels must not have leading zeroes", version)
		}
	}
	return nil
}

func validateModule() error {
	// Let Go parse its own module file. This command neither resolves modules nor
	// writes go.mod; force local/offline operation independently of caller setup.
	cmd := exec.Command("go", "mod", "edit", "-json", "go.mod")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("read go.mod metadata: %w", err)
	}
	var metadata struct {
		Module *struct {
			Path string
		}
		Replace []struct {
			Old struct {
				Path string
			}
			New struct {
				Path    string
				Version string
			}
		}
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("decode go.mod metadata: %w", err)
	}
	if metadata.Module == nil || metadata.Module.Path != modulePath {
		return fmt.Errorf("go.mod must declare module %s", modulePath)
	}
	for _, replacement := range metadata.Replace {
		if replacement.New.Version == "" {
			return fmt.Errorf("local replacement is not releasable: %s => %s", replacement.Old.Path, replacement.New.Path)
		}
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "release preflight:", err)
	os.Exit(1)
}
