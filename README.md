# Mycoria

Mycoria gives you the connectivity freedom of the original Internet.

- Everyone is equal: Easily connect to anyone.
- Everyone is welcome: Open network without bureaucracy.
- No spooking: Everthing is authenticated.
- No surveillance: Everything is encrypted.
- No barriers: Connect via the Internet or extend Mycoria with your own mesh.

Design Goals

- Keep it small and simple
- Compatible with existing infrastructure (eg. DNS)
- Secure by default
- Private by default (WIP)

Main Features

- Automatic end-to-end encryption
- Modern cryptography
- Smart and scalable routing (partly WIP)
- Resolve .myco DNS (OS configuration required)
- Rotating private addresses (WIP)
- Dashboard (WIP)
- Auto-Optimization/Healing of Network (for Internet overlay; WIP)
- Simple Service Discovery (WIP)

Read more on [mycoria.org](https://mycoria.org).

## Supported Platforms

Currently only Linux amd64 is being tested. Linux arm64 should work as well.
Windows will follow soon.

We are also looking into supporting smaller devices in order to bring this to the IoT world.

## Packaging and Deployment

See [./packaging](./packaging).

## Building

0. Install Go

1. Run `./build` in `cmd/mycoria`
