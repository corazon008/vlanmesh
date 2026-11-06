package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"vlanmesh/internal/model"
)

const sendSpacing = 100 * time.Millisecond

// Probe sends count ICMP echoes from srcIP (bound to iface) to dstIP and
// returns a classified result.
//
// SO_BINDTODEVICE is mandatory: without it the kernel would route the packet
// straight out of the destination VLAN's leg and bypass the firewall.
func Probe(srcIP, iface, dstIP string, count int, timeout time.Duration) model.Result {
	res := model.Result{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Started: time.Now(),
	}
	fail := func(err error) model.Result {
		res.Status = model.StatusError
		res.Err = err.Error()
		res.Duration = float64(time.Since(res.Started).Microseconds()) / 1000
		return res
	}

	dst := net.ParseIP(dstIP)
	if dst == nil {
		return fail(fmt.Errorf("invalid destination %q", dstIP))
	}
	if net.ParseIP(srcIP) == nil {
		return fail(fmt.Errorf("invalid source %q", srcIP))
	}

	conn, err := net.ListenPacket("ip4:icmp", srcIP)
	if err != nil {
		return fail(fmt.Errorf("raw icmp socket on %s: %w (need CAP_NET_RAW)", srcIP, err))
	}
	defer conn.Close()

	ipc, ok := conn.(*net.IPConn)
	if !ok {
		return fail(fmt.Errorf("unexpected connection type %T", conn))
	}
	if err := bindToDevice(ipc, iface); err != nil {
		return fail(err)
	}

	id := rand.IntN(0xffff)
	payload := []byte("vlanmesh")
	sendNano := make([]atomic.Int64, count+1)

	// Reader runs concurrently with the sender so the first reply is not
	// delayed by the send spacing.
	var (
		seen       = make(map[int]bool, count)
		rtts       []float64
		icmpType   int
		icmpCode   int
		errText    string
		buf        = make([]byte, 1500)
		deadline   = time.Now().Add(time.Duration(count-1)*sendSpacing + timeout)
		readerDone = make(chan struct{})
	)

	go func() {
		defer close(readerDone)
		_ = conn.SetReadDeadline(deadline)
		for len(seen) < count {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					return
				}
				if time.Now().After(deadline) {
					return
				}
				continue
			}
			now := time.Now()
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}

			switch body := m.Body.(type) {
			case *icmp.Echo:
				if m.Type != ipv4.ICMPTypeEchoReply {
					continue
				}
				if body.ID != id || body.Seq < 1 || body.Seq > count {
					continue
				}
				if ia, ok := addr.(*net.IPAddr); ok && !ia.IP.Equal(dst) {
					continue
				}
				if seen[body.Seq] {
					continue
				}
				seen[body.Seq] = true
				if at := sendNano[body.Seq].Load(); at != 0 {
					rtts = append(rtts, float64(now.UnixNano()-at)/1e6)
				}

			case *icmp.DstUnreach:
				if pid, seq, ok := innerIDSeq(body.Data); ok && pid == id && seq >= 1 && seq <= count {
					icmpType = numericType(m.Type)
					icmpCode = m.Code
					errText = fmt.Sprintf("icmp unreachable (type %d code %d)", icmpType, m.Code)
				}

			case *icmp.TimeExceeded:
				if pid, seq, ok := innerIDSeq(body.Data); ok && pid == id && seq >= 1 && seq <= count {
					icmpType = numericType(m.Type)
					icmpCode = m.Code
					errText = "icmp time exceeded"
				}
			}
		}
	}()

	for seq := 1; seq <= count; seq++ {
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			return fail(fmt.Errorf("marshal icmp: %w", err))
		}
		sendNano[seq].Store(time.Now().UnixNano())
		if _, err := conn.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
			return fail(fmt.Errorf("send icmp to %s via %s: %w (check policy routing)", dstIP, iface, err))
		}
		res.Sent++
		if seq < count {
			time.Sleep(sendSpacing)
		}
	}
	<-readerDone

	res.Recv = len(seen)
	res.ICMPType = icmpType
	res.ICMPCode = icmpCode
	res.Loss = 1 - float64(res.Recv)/float64(res.Sent)

	if res.Recv > 0 {
		res.RTTMin = rtts[0]
		res.RTTMax = rtts[0]
		var sum float64
		for _, r := range rtts {
			if r < res.RTTMin {
				res.RTTMin = r
			}
			if r > res.RTTMax {
				res.RTTMax = r
			}
			sum += r
		}
		res.RTTAvg = sum / float64(len(rtts))
		if res.Recv == res.Sent {
			res.Status = model.StatusOK
		} else {
			res.Status = model.StatusDegraded
		}
	} else {
		switch {
		case icmpType == 3 && (icmpCode == 9 || icmpCode == 10 || icmpCode == 13):
			res.Status = model.StatusRejected
		case icmpType == 3, icmpType == 11:
			res.Status = model.StatusUnreachable
		default:
			res.Status = model.StatusTimeout
		}
		res.Err = errText
	}

	res.Duration = float64(time.Since(res.Started).Microseconds()) / 1000
	return res
}

func bindToDevice(conn *net.IPConn, iface string) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}
	var soErr error
	if err := sc.Control(func(fd uintptr) {
		soErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
	}); err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if soErr != nil {
		return fmt.Errorf("SO_BINDTODEVICE %s: %w", iface, soErr)
	}
	return nil
}

// numericType converts an icmp.Type interface to the IPv4 numeric type.
func numericType(t icmp.Type) int {
	if v, ok := t.(ipv4.ICMPType); ok {
		return int(v)
	}
	return 0
}

// innerIDSeq extracts the ICMP ID/seq of the original datagram embedded in an
// ICMP error message.
func innerIDSeq(data []byte) (id, seq int, ok bool) {
	if len(data) < 28 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return 0, 0, false
	}
	return int(binary.BigEndian.Uint16(data[ihl+4 : ihl+6])),
		int(binary.BigEndian.Uint16(data[ihl+6 : ihl+8])), true
}
