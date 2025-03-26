// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sctp

import "time"

// flags set upon calling ReadMsg in recvFlags
const (
	// SCTP_NOTIFICATION indicates that the received message is
	// an SCTP event and not a data message.
	SCTP_NOTIFICATION = 0x8000

	// SCTP_EOR indicates the end of a message (End Of Record).
	// See SCTPConn.ReadMsgExt for more details
	SCTP_EOR = 0x80 // unix.MSG_EOR

	// SCTP_CTRUNC indicates the ancillary data was truncated.
	// See SCTPConn.ReadMsgExt for more details
	SCTP_CTRUNC = 0x8 // unix.MSG_CTRUNC
)

// InitOptions structure provides information for initializing new SCTP associations
type InitOptions struct {
	// Number of streams to which the application wishes to be able to send, 10 by default
	NumOstreams uint16
	// Maximum number of inbound streams the application is prepared to support, 10 by default
	MaxInstreams uint16
	// How many attempts the SCTP endpoint should make at resending the INIT
	// if not specified the kernel parameter net.sctp.max_init_retransmits is used as default
	MaxAttempts uint16
	// Largest timeout or retransmission timeout (RTO) value (in milliseconds) to use in attempting an INIT
	// if not specified the kernel parameter net.sctp.rto_max is used as default
	MaxInitTimeout uint16

	// Default value for read and write buffers is 512K (usually the linux kernel doubles this value)
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

	// Heartbeat specifies the heartbeat period for network associations.
	// If zero, heartbeats are enabled and current setting of the heartbeats interval is left unchanged
	// If negative, heartbeats are disabled.
	//
	// SCTP heartbeats are enabled by default and the interval between them are defined
	// in `net.sctp.hb_interval` kernel parameter which is 30 seconds by default.
	//
	// These parameter apply for all remote addresses of an association (multi-homing).
	// If you want different values for different remote addresses you can use the
	// SCTPConn.SetHeartbeat function
	Heartbeat time.Duration
}

// SndInfo structure specifies SCTP options for sending SCTP messages
// Used in SCTPConn.WriteMsg functions
type SndInfo struct {
	// Sid value holds the stream number to which the application
	// wishes to send this message.  If a sender specifies an invalid
	// stream number, an error indication is returned and the call fails
	Sid uint16

	// Flags field is composed of a bitwise OR of the values
	// defined in SndInfo flags
	Flags uint16

	// Payload protocol identifier
	Ppid uint32

	// This value is an opaque 32-bit context datum that is
	// used in WriteMsg() functions.  This value is passed back to the
	// upper layer if an error occurs on the send of a message and is
	// retrieved with each undelivered message
	Context uint32

	// Association Id is ignored in one-to-one mode
	AssocId int32
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
	SCTP_EOF = 0x200 // unix.MSG_FIN
)

// RcvInfo structure describes SCTP receive information about a received message
// RcvInfo is returned by SCTPConn.ReadMsg function
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

	// Association Id is ignored in one-to-one mode
	AssocId int32
}

// Status structure holds current status information about an
// association, including association state, peer receiver window size,
// number of unacknowledged DATA chunks, and number of DATA chunks
// pending receipt.
type Status struct {
	// Association Id is ignored in one-to-one mode
	AssocId int32

	// Contains the association's current state, i.e.,
	// one of the values defined in Status state values.
	State int32

	// Contains the association peer's current receiver window size.
	Rwnd uint32

	// Number of unacknowledged DATA chunks.
	UnackData uint16

	// Number of DATA chunks pending receipt.
	PendingData uint16

	// Number of streams that the peer will be using outbound.
	InStreams uint16

	// Number of outbound streams that the endpoint is allowed to use.
	OutStreams uint16

	// The size at which SCTP fragmentation will occur.
	FragmentationPoint uint32

	// Information on the current primary peer address.
	PrimaryAddrInfo *PeerAddrInfo
}

// Status state values
const (
	SCTP_EMPTY             = 0
	SCTP_CLOSED            = 1
	SCTP_COOKIE_WAIT       = 2
	SCTP_COOKIE_ECHOED     = 3
	SCTP_ESTABLISHED       = 4
	SCTP_SHUTDOWN_PENDING  = 5
	SCTP_SHUTDOWN_SENT     = 6
	SCTP_SHUTDOWN_RECEIVED = 7
	SCTP_SHUTDOWN_ACK_SENT = 8
)

// PeerAddrInfo contains information about a specific peer address
// of an association, including its reachability state, congestion
// window, and retransmission timer values.
type PeerAddrInfo struct {
	// Association Id is ignored in one-to-one mode
	AssocId int32

	// This is filled by the application and contains the
	// peer address of interest.
	Addr *SCTPAddr

	// Contains the peer address's state. See PeerAddrInfo state values
	State int32

	// Contains the peer address's current congestion window.
	Cwnd uint32

	// Contains the peer address's current smoothed
	// round-trip time calculation in milliseconds.
	Srtt uint32

	// Contains the peer address's current retransmission
	// timeout value in milliseconds.
	Rto uint32

	// Contains the current Path MTU of the peer address.  It is
	// the number of bytes available in an SCTP packet for chunks.
	Mtu uint32
}

// PeerAddrInfo state values
const (
	// SCTP_UNCONFIRMED is the initial state of a peer address.
	SCTP_UNCONFIRMED = 3

	// SCTP_ACTIVE state is entered the first time after path
	// verification.  It can also be entered if the state is
	// SCTP_INACTIVE and the path supervision detects that the peer
	// address is reachable again.
	SCTP_ACTIVE = 2

	// SCTP_INACTIVE state is entered whenever a path failure is detected.
	SCTP_INACTIVE = 0
)
