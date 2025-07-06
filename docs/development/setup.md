# Development Setup

## Adding a new capability

To add a new scan to networkscan, providing new enumeration capabilities to security operators everywhere, please see the [adding a new capability](./adding.md) page.

## Setting up your development environment

If you've just cloned networkscan for the first time, welcome to the community! We use Palantir's [godel](https://github.com/palantir/godel) to streamline local development and [goreleaser](https://goreleaser.com/) to handle the heavy lifting on the release process.

To get started with godel, you can run

```bash
./godelw verify
```

This will run a number of checks for us, including linters, tests, and license checks. We run this command as part of our CI pipeline to ensure the codebase is consistently passing tests.

## Building the CLI

We can use godel to build our CLI locally by running

```bash
./godelw build
```

You should see output in `out/build/networkscan/<version>/<os>-<arch>/networkscan`.

If you'd like to clean this output up, you can run

```bash
./godelw clean
```

## Compile and Run in single step

If you are developing a new command or subcommand, and want to test, you can run with:

```bash
go run main.go <command>
```

For example, the following commands would be the same, but the former requires building the CLI first:

```bash
networkscan discover port --targets 127.0.0.1 --ports 22 --ports 80
go run main.go discover port --target 127.0.0.1 --ports 22 --ports 80
```

If you are dealing with a command or subcommand that requires a privileged user to run, on a Unix based machine a quick way to do this is:

```bash
sudo $(which go) run main.go discover port --target 192.168.0.0 --ports 443
```

## Testing releases locally

We can use goreleaser locally as well to test our builds. As networkscan uses [cosign](https://github.com/sigstore/cosign) to sign our artifacts and Docker containers during our CI pipeline, we'll want to skip this step when running locally.

```bash
goreleaser release --snapshot --clean --skip sign
```

This should output binaries, distributable tarballs/zips, as well as docker images to your local machine's Docker registry.
