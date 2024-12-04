//go:build linux

package sctp

import (
	"golang.org/x/sys/unix"
)

const (
	SCTP_SACK_IMMEDIATELY = 8
	SCTP_PR_SCTP_ALL      = 128
	SCTP_NOTIFICATION     = 0x8000
)

const (
	SCTP_EOR = unix.MSG_EOR
)

// InitOptions structure provides information for initializing new SCTP associations
type InitOptions struct {
	// number of streams to which the application wishes to be able to send, 10 by default
	NumOstreams uint16
	// maximum number of inbound streams the application is prepared to support, 10 by default
	MaxInstreams uint16
	// how many attempts the SCTP endpoint should make at resending the INIT
	// if not specified the kernel parameter net.sctp.max_init_retransmits is used as default
	MaxAttempts uint16
	// largest timeout or retransmission timeout (RTO) value (in milliseconds) to use in attempting an INIT
	// if not specified the kernel parameter net.sctp.rto_max is used as default
	MaxInitTimeout uint16

	// Default values for read and write buffers is 512K (usually the linux kernel doubles this value)
	// Note that buffer sizes are limited by the kernel parameters `net.core.rmem_max` and `net.core.wmem_max`
	// unless we run as a privileged user
	SocketReadBufferSize  int
	SocketWriteBufferSize int

	// This option requests that the local endpoint set the specified
	// Adaptation Layer Indication parameter. If the value is `true`
	// the Adaptation Layer Indication parameter is set to the value
	// specified in the AdaptationIndication field.
	AdaptationIndicationEnabled bool
	AdaptationIndication        uint32
}

// SndInfo structure specifies SCTP options for sending SCTP messages
type SndInfo struct {
	// Sid value holds the stream number to which the application
	// wishes to send this message.  If a sender specifies an invalid
	// stream number, an error indication is returned and the call fails
	Sid uint16

	// Flags:  This field is composed of a bitwise OR of the values
	// defined in SndInfo flags
	Flags uint16

	// Payload protocol identifier
	Ppid uint32

	// This value is an opaque 32-bit context datum that is
	// used in WriteMsg() functions.  This value is passed back to the
	// upper layer if an error occurs on the send of a message and is
	// retrieved with each undelivered message
	Context uint32

	// Association ID is ignored in one-to-one mode
	AssocID int32
}

// SndInfo flags
const (
	// SCTP_UNORDERED flag requests the unordered delivery of the
	// message.  If this flag is clear, the datagram is considered an
	// ordered send.
	SCTP_UNORDERED = 1

	// SCTP_ADDR_OVER is filled automatically by WriteMsg function,
	// when a 'to' address is specified
	SCTP_ADDR_OVER = 2

	// SCTP_ABORT causes the specified association to
	// abort by sending an ABORT message to the peer.  The ABORT chunk
	// will contain an error cause of 'User Initiated Abort' with
	// cause code 12.  The cause-specific information of this error
	// cause is provided in the byte buffer passed in.
	SCTP_ABORT = 4

	// SCTP_SENDALL has no effect for the one-to-one style socket
	SCTP_SENDALL = 64

	// SCTP_EOF invokes the SCTP graceful shutdown
	// procedures on the specified association.  Graceful shutdown
	// assures that all data queued by both endpoints is successfully
	// transmitted before closing the association.
	SCTP_EOF = unix.MSG_FIN
)

// RcvInfo structure describes SCTP receive information about a received message
type RcvInfo struct {
	// The SCTP stack places the message's stream number in this value.
	Sid uint16

	// This value contains the stream sequence number that the
	// remote endpoint placed in the DATA chunk.  For fragmented
	// messages, this is the same number for all deliveries of the
	// message (if more than one recvmsg() is needed to read the message).
	Ssn uint16

	// This field may contain any of the following flags and is
	// composed of a bitwise OR of these values:
	//
	// SCTP_UNORDERED:  This flag is present when the message was sent unordered.
	Flags uint16

	// Explicit padding to align Ppid to a 4-byte boundary
	_ uint16

	// Payload protocol identifier
	Ppid uint32

	// TSN that was assigned to one of the SCTP DATA chunks
	Tsn uint32

	// Current cumulative TSN as known by the underlying SCTP layer.
	Cumtsn uint32

	// This value is an opaque 32-bit context datum that was
	// set by the user with the SCTP_CONTEXT socket option.  This value
	// is passed back to the upper layer if an error occurs on the send
	// of a message and is retrieved with each undelivered message.
	Context uint32

	// Association ID is ignored in one-to-one mode
	AssocID int32
}

// TODO: In refreshRemoteAddr if getRemoteAddr fails, use GetPeerAddr
// WriteMsg(byte, snd_info)
// WriteMsgTo
// WriteMsgEor
// WriteMsgToEor
// if other flags should be set? except EOR?
// WriteMsgExt(buf, snd_info, to, flags)

// TODO: Add test from net.net_test.go (regarding Closing, Close read, close write etc)
// TODO: Add test from net.protoconn_test.go (regarding specific methods of Conn, SCTPConn etc)
// TODO: Add test from timeout_test.go
// TODO: Add test from write_unix_test.go
// TODO: Add test from conn_test.go
// TODO: Add test from dial_unix_test.go
// TODO: Test for timeouts with Accept (setReadDeadLine)
