package sctp

import (
	"errors"
	"net"
	"strconv"
	"unsafe"
)

type EventType int

// event types
const (
	_SCTP_SN_TYPE_BASE = EventType(iota + (1 << 15))
	SCTP_ASSOC_CHANGE
	SCTP_PEER_ADDR_CHANGE
	_SCTP_SEND_FAILED // use SCTP_SEND_FAILED_EVENT
	SCTP_REMOTE_ERROR
	SCTP_SHUTDOWN_EVENT
	SCTP_PARTIAL_DELIVERY_EVENT
	SCTP_ADAPTATION_INDICATION
	SCTP_AUTHENTICATION_EVENT
	SCTP_SENDER_DRY_EVENT
	SCTP_STREAM_RESET_EVENT
	SCTP_ASSOC_RESET_EVENT
	SCTP_STREAM_CHANGE_EVENT
	SCTP_SEND_FAILED_EVENT
)

// SCTP_ASSOC_CHANGE state
const (
	// SCTP_COMM_UP shows that a new association is now ready, and data may be
	// exchanged with this peer.  When an association has been
	// established successfully, this notification should be the first one.
	SCTP_COMM_UP = iota

	// SCTP_COMM_LOST shows that the association has failed.  The association is
	// now in the closed state.  If SEND_FAILED notifications are
	// turned on, an SCTP_COMM_LOST is accompanied by a series of
	// SCTP_SEND_FAILED_EVENT events, one for each outstanding message.
	SCTP_COMM_LOST

	// SCTP_RESTART shows that the peer has restarted.
	SCTP_RESTART

	// SCTP_SHUTDOWN_COMP means the association has gracefully closed.
	SCTP_SHUTDOWN_COMP

	// SCTP_CANT_STR_ASSOC shows that the association setup failed.
	SCTP_CANT_STR_ASSOC
)

// SCTP_PEER_ADDR_CHANGE state
const (
	// SCTP_ADDR_AVAILABLE shows that this address is now reachable.  This
	// notification is provided whenever an address becomes reachable.
	SCTP_ADDR_AVAILABLE = iota

	// SCTP_ADDR_UNREACHABLE shows that the address specified can no longer be
	// reached.  Any data sent to this address is rerouted to an
	// alternate until this address becomes reachable.  This
	// notification is provided whenever an address becomes
	// unreachable.
	SCTP_ADDR_UNREACHABLE

	// SCTP_ADDR_REMOVED shows that the address is no longer part of the association.
	SCTP_ADDR_REMOVED

	// SCTP_ADDR_ADDED shows that the address is now part of the association.
	SCTP_ADDR_ADDED

	// SCTP_ADDR_MADE_PRIM shows that this address has now been made the primary
	// destination address.  This notification is provided whenever an
	// address is made primary.
	SCTP_ADDR_MADE_PRIM

	SCTP_ADDR_CONFIRMED
	SCTP_ADDR_POTENTIALLY_FAILED
)

type Event interface {
	Type() EventType
	Flags() int
}

// AssocChangeEvent informs the application that an SCTP
// association has either started or ended.
type AssocChangeEvent struct {
	// One of SCTP_ASSOC_CHANGE states
	State uint16

	// If the state was reached due to an error condition (e.g.,
	// SCTP_COMM_LOST), any relevant error information is available in
	// this field.  This corresponds to the protocol error codes defined
	// in [RFC4960].
	Error uint16

	// Maximum number of outbound streams
	OutboundStreams uint16

	// Maximum number of inbound streams
	InboundStreams uint16

	// Association ID is ignored in one-to-one mode
	AssocID int32

	// Additional information. See [RFC6458]#section-6.1.1
	Info []byte
}

func (*AssocChangeEvent) Type() EventType { return SCTP_ASSOC_CHANGE }

// Flags is ignored for this event
func (*AssocChangeEvent) Flags() int { return 0 }

// PeerAddrChangeEvent is sent When a destination address of a
// multi-homed peer encounters a state change.
// Reception of PeerAddrChangeEvent when the peer adds or removes
// addresses to/from the association is affected by `net.sctp.addip_enable`
// and `net.sctp.addip_noauth_enable` kernel parameters.
type PeerAddrChangeEvent struct {
	// The affected address field holds the remote peer's
	// address that is encountering the change of state
	Addr net.IPAddr

	// One of SCTP_PEER_ADDR_CHANGE states
	State uint32

	// If the state was reached due to any error condition
	// (e.g., SCTP_ADDR_UNREACHABLE), any relevant error information is
	// available in this field
	Error uint32

	// Association ID is ignored in one-to-one mode
	AssocID int32
}

func (*PeerAddrChangeEvent) Type() EventType { return SCTP_PEER_ADDR_CHANGE }

// Flags is ignored for this event
func (*PeerAddrChangeEvent) Flags() int { return 0 }

type RemoteErrorEvent struct {
	Error uint16

	// Association ID is ignored in one-to-one mode
	AssocID int32

	// This contains the ERROR chunk as defined in Section 3.3.10
	// of the SCTP specification [RFC4960].
	Data []byte
}

func (*RemoteErrorEvent) Type() EventType { return SCTP_REMOTE_ERROR }

// Flags is ignored for this event
func (*RemoteErrorEvent) Flags() int { return 0 }

// ShutdownEvent is received to inform the application
// that it should cease sending data.
type ShutdownEvent struct {
	// Association ID is ignored in one-to-one mode
	AssocID int32
}

func (*ShutdownEvent) Type() EventType { return SCTP_SHUTDOWN_EVENT }

// Flags is ignored for this event
func (*ShutdownEvent) Flags() int { return 0 }

type eventHeader struct {
	snType   uint16
	snFlags  uint16
	snLength uint32
}

func ParseEvent(b []byte) (Event, error) {
	if len(b) < int(unsafe.Sizeof(eventHeader{})) {
		return nil, errors.New("event too short")
	}
	hdr := (*eventHeader)(unsafe.Pointer(&b[0]))
	switch EventType(hdr.snType) {
	case SCTP_ASSOC_CHANGE:
		return parseAssocChangeEvent(b)
	case SCTP_PEER_ADDR_CHANGE:
		return parsePeerAddrChangeEvent(b)
	case _SCTP_SEND_FAILED:
		return nil, errors.New("SCTP_SEND_FAILED not implemented, use SCTP_SEND_FAILED_EVENT")
	case SCTP_REMOTE_ERROR:
		return parseRemoteErrorEvent(b)
	case SCTP_SHUTDOWN_EVENT:
		return parseShutdownEvent(b)
	//case SCTP_PARTIAL_DELIVERY_EVENT:
	//case SCTP_ADAPTATION_INDICATION:
	//case SCTP_AUTHENTICATION_EVENT:
	//case SCTP_SENDER_DRY_EVENT:
	//case SCTP_STREAM_RESET_EVENT:
	//case SCTP_ASSOC_RESET_EVENT:
	//case SCTP_STREAM_CHANGE_EVENT:
	//case SCTP_SEND_FAILED_EVENT:
	default:
		return nil, errors.New("unknown event type: " + strconv.Itoa(int(hdr.snType)))
	}
}

func parseAssocChangeEvent(b []byte) (*AssocChangeEvent, error) {
	type assocChangeEvent struct {
		eventHeader
		state           uint16
		error           uint16
		outboundStreams uint16
		inboundStreams  uint16
		assocID         int32
	}
	if len(b) < int(unsafe.Sizeof(assocChangeEvent{})) {
		return nil, errors.New("assocChangeEvent event too short")
	}

	ace := (*assocChangeEvent)(unsafe.Pointer(&b[0]))
	sizeOfAce := unsafe.Sizeof(assocChangeEvent{})
	return &AssocChangeEvent{
		State:           ace.state,
		Error:           ace.error,
		OutboundStreams: ace.outboundStreams,
		InboundStreams:  ace.inboundStreams,
		AssocID:         ace.assocID,
		Info:            b[sizeOfAce:],
	}, nil
}

func parsePeerAddrChangeEvent(b []byte) (*PeerAddrChangeEvent, error) {
	type peerAddrChangeEvent struct {
		eventHeader
		addr    [128]byte // sizeof(sockaddr_storage)
		state   uint32
		error   uint32
		assocID int32
	}
	if len(b) < int(unsafe.Sizeof(peerAddrChangeEvent{})) {
		return nil, errors.New("peerAddrChangeEvent event too short")
	}

	pace := (*peerAddrChangeEvent)(unsafe.Pointer(&b[0]))
	sctpAddr, err := fromSockaddrBuff(pace.addr[:], 1)
	if err != nil {
		return nil, err
	}
	return &PeerAddrChangeEvent{
		Addr:    sctpAddr.IPAddrs[0],
		State:   pace.state,
		Error:   pace.error,
		AssocID: pace.assocID,
	}, nil
}

func parseRemoteErrorEvent(b []byte) (Event, error) {
	type remoteErrorEvent struct {
		eventHeader
		error   uint16
		_       uint16 // explicit padding
		assocID int32
	}
	if len(b) < int(unsafe.Sizeof(remoteErrorEvent{})) {
		return nil, errors.New("remoteErrorEvent event too short")
	}

	ree := (*remoteErrorEvent)(unsafe.Pointer(&b[0]))

	// convert error to host byte order
	e := (*[2]byte)(unsafe.Pointer(&ree.error))
	eHost := int(e[0])<<8 + int(e[1])

	sizeOfRee := unsafe.Sizeof(remoteErrorEvent{})
	return &RemoteErrorEvent{
		Error:   uint16(eHost),
		AssocID: ree.assocID,
		Data:    b[sizeOfRee:],
	}, nil
}

func parseShutdownEvent(b []byte) (Event, error) {
	type shutdownEvent struct {
		eventHeader
		assocID int32
	}
	if len(b) < int(unsafe.Sizeof(shutdownEvent{})) {
		return nil, errors.New("shutdownEvent event too short")
	}

	se := (*shutdownEvent)(unsafe.Pointer(&b[0]))
	return &ShutdownEvent{
		AssocID: se.assocID,
	}, nil
}
