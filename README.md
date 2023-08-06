[![CodeQL](https://github.com/blck-snwmn/proxymitm/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/blck-snwmn/proxymitm/actions/workflows/github-code-scanning/codeql)

sample proxy uing mitm

## Usage
1. create certificate
1. server run
1. do
    ```bash
    curl https://target -x localhost:18080 --cacert your_ca_path
    ```
