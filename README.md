# pan-os-syslog

## Summary

Parse syslog traffic from PAN-OS. The data types in this library are
optimized for decoding logs, not for creating them. On consumer-grade
hardware, the benchmark suite demonstrates that 500-byte traffic logs are
parsed in under one microsecond. Contributions are welcome.

## Sources

This repository includes:

* A library for parsing PAN-OS syslog traffic (`src/`). Using
  `cabal-install` version 3.0+, this is built with `cabal build`.
* A test suite (`test/`) and a benchmark suite (`bench/`) that
  operate on the same logs (`common/Sample.hs`). These are built
  with `cabal build test` and `cabal build bench` respectively.
* An executable that validates logs from `stdin` (`scripts/validate.hs`).
  To build this, first run `cabal build --write-ghc-environment-files=always`.
  Then run `ghc scripts/validate`. Then, validate logs with
  `scripts/validate < /path/to/logs.txt`.

## Goals

This project's goals are:
.
* Support as many PAN-OS syslog types as possible: traffic,
  threat, hip-match, etc.
.
* Support as many versions of PAN-OS as possible: 8.0, 8.1, 9.0, etc.
.
* High performance. This library strives to avoid unneeded allocations.
  Some allocations cannot be avoided. For example, it is necessary to
  allocate space for the results. 
.
* Do a minimum amount of useful work on each field. The reasoning is
  that users will typically discard most of the fields, so there is
  no point wasting clock cycles doing unneeded work. Its hard to define
  what this is precisely. Roughly, the rule we follow is that integral
  fields are parsed as @Word64@, and non-integral fields are @Bytes@.
  We never attempt to validate hostnames, URIs, etc.
.
A good way to think about this library is that it is kind of like
a tokenizer. It is the first step when parsing PAN-OS logs into
some application-specific data type. There almost certainly needs
to be a second step to decodes fields that are actually of interest
to an application. This second step may involve validating URIs,
splitting the user domain and user name, etc.
