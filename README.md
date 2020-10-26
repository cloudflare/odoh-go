# [Oblivious DoH](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh)

[![CircleCI](https://circleci.com/gh/chris-wood/odoh.svg?style=svg)](https://circleci.com/gh/chris-wood/odoh)
[![Coverage Status](https://coveralls.io/repos/github/chris-wood/odoh/badge.svg?branch=master)](https://coveralls.io/github/chris-wood/odoh?branch=master)
[![GoDoc](https://godoc.org/github.com/chris-wood/odoh?status.svg)](https://godoc.org/github.com/chris-wood/odoh)

This library implements draft -02 of [Oblivious DoH](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-02). 

## Test vector generation

To generate test vectors, run:

```
$ ODOH_TEST_VECTORS_OUT=test-vectors.json go test -v -run TestVectorGenerate
```

To check test vectors, run:

```
$ ODOH_TEST_VECTORS_IN=test-vectors.json go test -v -run TestVectorVerify
```
