# vulncounter

This script is meant to take the output of [github-container-list](https://github.com/metalstormbass/github-container-list) and count the vulnerabilities.

## Usage:

First, run [github-container-list](https://github.com/metalstormbass/github-container-list) and generate a text file.

```
go run main.go metalstormbass main  > out.txt
```

Then run this tool

```
go run main.go out.txt
```