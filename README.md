# SCTP for Go

[![Go Tests](https://github.com/georgeyanev/go-sctp/actions/workflows/test.yml/badge.svg)](https://github.com/georgeyanev/go-sctp/actions/workflows/test.yml)

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
