[![CodeQL](https://github.com/blck-snwmn/proxymitm/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/blck-snwmn/proxymitm/actions/workflows/github-code-scanning/codeql)

sample proxy uing mitm

## Usage
1. create certificate
1. server run
1. do
    ```bash
    curl https://target -x localhost:18080 --cacert your_ca_path
    ```

## Development

CLI tools (`lefthook`) are managed by [aqua](https://aquaproj.github.io/) with versions pinned in [aqua.yaml](aqua.yaml).

### Install tools

Install aqua itself first (see the [aqua installation guide](https://aquaproj.github.io/docs/install)), then install the pinned tools:

```bash
aqua install
```

### Set up git hooks

[lefthook](lefthook.yml) runs lint checks on staged `*.go` files before each commit. Register the hooks once after cloning:

```bash
lefthook install
```
