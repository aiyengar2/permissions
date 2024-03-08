# permissions

A Go library for manipulating ACL permissions in a platform-agnostic way (Linux or Windows).

## How is this different from [`hectane/go-acl`](https://github.com/hectane/go-acl)?

This project was inspired by [`hectane/go-acl`](https://github.com/hectane/go-acl), but it has been updated to a newer Go version.

As a result, it uses the primitives from [`golang.org/x/sys/windows`](https://pkg.go.dev/golang.org/x/sys/windows) instead of defining them in the `api` package.
