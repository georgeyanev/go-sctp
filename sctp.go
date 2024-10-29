//go:build linux

package sctp

const (
	SCTP_INITMSG = 2

	SOL_SCTP = 132

	// SCTP_ADDRS_BUF_SIZE is the allocated buffer for system calls returning local/remote sctp multi-homed addresses
	SCTP_ADDRS_BUF_SIZE = 4096 //enough for most cases
)

// InitMsg structure provides information for initializing new SCTP associations
type InitMsg struct {
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
}

// TODO: add exported and internal methods for Bind and RemoveBind (BindRemove)
// TODO: Add SCTPListener implementing net.Listener interface
// TODO:  keep sctp.Addr instead of sctp.SCTPAddr and sctp.Conn instead of sctp.SCTPConn
