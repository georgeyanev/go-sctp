# SCTP for Go

[![Go Tests](https://github.com/georgeyanev/go-sctp/actions/workflows/test.yml/badge.svg)](https://github.com/georgeyanev/go-sctp/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/georgeyanev/go-sctp.svg)](https://pkg.go.dev/github.com/georgeyanev/go-sctp)
[![codecov](https://codecov.io/gh/georgeyanev/go-sctp/graph/badge.svg?token=QT0VLRUEJE)](https://codecov.io/gh/georgeyanev/go-sctp)
[![Fork me on GitHub](https://img.shields.io/badge/Fork%20me%20on-GitHub-blue?style=flat-square)](https://github.com/georgeyanev/go-sctp/fork)

**`go-sctp`** is a Golang package that provides an efficient interface for working 
with the **Stream Control Transmission Protocol (SCTP)**.
SCTP support in the Go ecosystem has been sparse and **`go-sctp`** aims to fill this gap. It offers high-level abstractions 
like `SCTPConn`, `SCTPListener`, and `SCTPAddr`, seamlessly integrating with Go's `net` 
package by implementing `net.Conn`, `net.Listener`, and `net.Addr`. Also, it integrates with Go's runtime 
network poller to provide asynchronous low-level I/O and deadline support.

This library supports SCTP's **one-to-one mode** and is designed specifically for **Linux** 
environments. It mimics most of the **TCP functionality** implemented in Go's `net` package, with added support for 
**multihoming**, **multistreaming** and **SCTP notifications**.  

**`go-sctp`** interfaces directly with the kernel SCTP module, leveraging system calls provided by Go's `unix` 
and `syscall` packages. This eliminates the need for external SCTP libraries, ensuring a lightweight,
efficient, and dependency-free implementation.

Well-structured and comprehensive documentation is prioritized as part of the development process.

---

## Features

  - Support for one-to-one SCTP mode (SOCK_STREAM socket type)
  - Use of non-blocking sockets
  - Integration with go's runtime network poller through os.File
  - Dial, Listen, Accept functionality following Go's TCP implementation logic
  - Basic SCTP read and write through SCTPConn.Read and SCTPConn.Write
  - Enhanced SCTP read and write through SCTPConn.ReadMsg and SCTPConn.WriteMsg
  - Deadline support for read/write/accept operations
  - Multi-streaming support through sctp.SndInfo and sctp.RcvInfo structures
  - Multi-homing support embedded in SCTPAddr
  - SCTP Notifications support
  - Exported socket options (i.e. SCTP_ADAPTATION_LAYER, SCTP_DISABLE_FRAGMENTS)
  - Runtime re-binding support through BindAdd and BindRemove
  - Shutdown and Abort support
  - Heartbeat management support
  - Most of the TCP tests in Go's net package applied here to SCTP
  - Well documented

For a complete list of features and the history of changes introduced in each version, refer to the
[CHANGELOG.md](https://github.com/georgeyanev/go-sctp/blob/master/CHANGELOG.md).

---

## Getting
  ```
  go get -u github.com/georgeyanev/go-sctp
  
  ```

---

## Usage

Most functionality mirrors Go's TCP implementation, making it intuitive to use. For example:

### Dial:
  ```go
  conn, err := sctp.Dial("sctp4", "127.0.0.1/127.0.0.2:3868")
  ```

### Listen:
  ```go
  ln, err := sctp.Listen("sctp4", "127.0.0.1/127.0.0.2:3868")
  ```

### Accept:
  ```go
  conn, err := ln.Accept()
  ```

### Kernel parameters:
For optimal performance set the kernel parameters
`net.core.rmem_max` and `net.core.wmem_max` to at least 512KB

---

## Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to contribute code, feel free to open an issue or pull request.
