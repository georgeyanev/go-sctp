# Changelog

## v1.0.0
### Add
- Introduce `CookieLife` field in `InitOptions` and `AssocParams`.
- Add methods to get and set `CookieLife` (`assocInfo`, `setCookieLife`).
- Update `SCTPConn.Status` func to accept optional peer address.

## v0.13.0
### Add
- Heartbeat management through `Heartbeat` interval option in InitOptions and SCTPConn.SetHeartbeat function

## v0.12.0
### Add
- unsupported.go to return error on non-supported platforms, allowing go-sctp to compile on non-supported platforms

## v0.11.0
### Add
- SCTPConn.ReadMsgExt function allowing the user to pass a pre-allocated oob buffer
- Code coverage

## v0.10.0
### Add
- Initial release with core SCTP functionality, that including:
  - Support for one-to-one SCTP mode (SOCK_STREAM socket type)
  - Use of non-blocking sockets
  - Integration with go's runtime network poller through os.File
  - Dial, Listen, Accept functionality following Go's TCP implementation logic
  - Basic SCTP read and write through SCTPConn.Read and SCTPConn.Write
  - Enhanced SCTP read and write through SCTPConn.ReadMsg and SCTPConn.WriteMsg
  - Deadline support for read/write operations
  - Multi-streaming support through sctp.SndInfo and sctp.RcvInfo structures
  - Multi-homing support embedded in SCTPAddr
  - SCTP Notifications support, that including:
    - SCTP_ASSOC_CHANGE (with parse support)
    - SCTP_PEER_ADDR_CHANGE (with parse support)
    - SCTP_REMOTE_ERROR (with parse support)
    - SCTP_SHUTDOWN_EVENT (with parse support)
    - SCTP_PARTIAL_DELIVERY_EVENT 
    - SCTP_ADAPTATION_INDICATION (with parse support)
    - SCTP_AUTHENTICATION_EVENT
    - SCTP_SENDER_DRY_EVENT (with parse support)
    - SCTP_STREAM_RESET_EVENT
    - SCTP_ASSOC_RESET_EVENT
    - SCTP_STREAM_CHANGE_EVENT
    - SCTP_SEND_FAILED_EVENT (with parse support)
  - Exported socket options, that including:
    - SCTP_ADAPTATION_LAYER
    - SCTP_DISABLE_FRAGMENTS
    - SCTP_NODELAY
    - SCTP_STATUS
    - SO_LINGER
    - SO_RCVBUF
    - SO_SNDBUF
  - Runtime re-binding support through BindAdd and BindRemove
  - Shutdown and Abort support
  - Most of the TCP tests in Go's net package applied here to SCTP