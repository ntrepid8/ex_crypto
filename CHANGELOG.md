# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.10.0 - 2019-02-20

- Fixes
    - fix `ExCrypto.decrypt/3` and `ExCrypto.decrypt/5` error tuples
- Contributors (thanks!)
    - [AnilRedshift](https://github.com/AnilRedshift)

## v0.9.0 - 2018-03-15

- Enhancements
    - implement `Inspect` protocol for public/private RSA keys to protect private key data
    - add `get_fingerprint/2` for public/private RSA keys to generate fingerprints
    - add `encode_der/1` and `decode_der/*` for public/private RSA keys to support DER encoding
    - add `get_public/1` to create a public key from the private RSA key
- Contributors (thanks!)
    - [obrok](https://github.com/obrok)
    - [ntrepid8](https://github.com/ntrepid8)

## v0.8.0 - 2018-02-05

- Enhancements
    - remove warnings from Elixir 1.6.1 and Erlang/OTP 20
    - update code style and formatting via Elixir 1.6.1 formatter
- Contributors (thanks!)
    - [quatermain](https://github.com/quatermain)

## v0.7.1 - 2017-11-06

- Fixes
    - fix `generate_key` compatibility with OTP 20
    - fix README examples compatibility with Elixir v1.5
- Contributors (thanks!)
    - [Narnach](https://github.com/Narnach)
    - [denispeplin](https://github.com/denispeplin)

## v0.7.0 - 2017-10-27

- Enhancements
    - Add generate_key and pem_encode wrappers
    - Add support for OTP 20
    - Update Elixir requirement to 1.4.2
    - Add documentation & examples
    - Update Travis-CI to test OTP 18 & OTP 20
- Contributors (thanks!)
    - [barttenbrinke](https://github.com/barttenbrinke)

## v0.6.0 - 2017-10-23

- Enhancements
    - add support for RSA keys with passwords
- Contributors (thanks!)
    - [sheharyarn](https://github.com/sheharyarn)

## v0.5.0 - 2017-10-03

- Enhancements
    - update poison dependency (enable use with Poison 3.0)
- Contributors (thanks!)
    - [MarcAntoine-Arnaud](https://github.com/MarcAntoine-Arnaud)

## v0.4.0 - 2017-04-12

- Enhancements
  - add helpers for symmetric crypto tokens
  - cleanup various & sundry dialyzer/compiler warnings
- Contributors
  - [ntrepid8](https://github.com/ntrepid8)

## v0.3.0 - 2017-02-13

- Enhancements
  - add CBC mode
- Contributors
  - [bglusman](https://github.com/bglusman)
  - [ntrepid8](https://github.com/ntrepid8)
