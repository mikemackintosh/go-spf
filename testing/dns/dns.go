package dns

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

var TEST_VERBOSE = false

func init() {
	if len(os.Getenv("TEST_VERBOSE")) > 0 {
		TEST_VERBOSE = true
	}
}

var records map[string]string
var zones map[string]Zone

func init() {
	log.SetFlags(0)
}

type Zone struct {
	Domain string
	Txt    []RecordTxt
	A      []RecordA
	MX     []RecordMX
	CNAME  []RecordCNAME
}

type RecordTxt struct {
	Host  string
	Value string
	TTL   int
}

type RecordA struct {
	Host  string
	Value string
	TTL   int
}

type RecordMX struct {
	Host     string
	Value    string
	Priority int
	TTL      int
}

type RecordCNAME struct {
	Host  string
	Value string
	TTL   int
}

func Run() {
	fmt.Printf("--- Starting DNS server\n")

	zones = map[string]Zone{
		"mikemackintosh.com": Zone{
			Domain: "mikemackintosh.com",
			Txt: []RecordTxt{
				RecordTxt{
					Host:  "@",
					Value: "v=spf1 include:_spf.google.com ~all",
				},
			},
		},
		"google.com": Zone{
			Domain: "google.com",
			Txt: []RecordTxt{
				RecordTxt{
					Host:  "_spf",
					Value: "v=spf1 ip4:127.0.0.1/16 ~all",
				},
			},
		},
	}

	//Listen on UDP Port
	addr := net.UDPAddr{
		Port: 8053,
		IP:   net.ParseIP("127.0.0.1"),
	}
	u, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("--- ERROR:\n\t %s", err)
	}

	// Wait to get request on that port
	for {
		tmp := make([]byte, 1024)
		_, addr, _ := u.ReadFrom(tmp)
		packet := gopacket.NewPacket(tmp, layers.LayerTypeDNS, gopacket.Default)
		dnsPacket := packet.Layer(layers.LayerTypeDNS)
		tcp, _ := dnsPacket.(*layers.DNS)
		serveDNS(u, addr, tcp)
	}
}

func serveDNS(u *net.UDPConn, clientAddr net.Addr, request *layers.DNS) {
	replyMess := request
	var dnsAnswer layers.DNSResourceRecord
	var err error

	domain := strings.Split(string(request.Questions[0].Name), ".")
	if TEST_VERBOSE {
		fmt.Printf("\t--> domain: %#v\n", domain)
	}

	tld := domain[len(domain)-2:]
	if TEST_VERBOSE {
		fmt.Printf("\t--> tld: %s\n", strings.Join(tld, "."))
	}

	z := zones[strings.Join(tld, ".")]
	if TEST_VERBOSE {
		fmt.Printf("\t--> zones: %+v\n", z)
		fmt.Printf("\t--> q: %+v\n", string(request.Questions[0].Name))
	}

	host := strings.Join(domain[:len(domain)-2], ".")
	if host == "" {
		host = "@"
	}
	if TEST_VERBOSE {
		fmt.Printf("\t--> host: %+v\n", host)
	}

	dnsAnswer.Type = layers.DNSTypeTXT
	dnsAnswer.Name = []byte(request.Questions[0].Name)
	dnsAnswer.Class = layers.DNSClassIN

	switch request.Questions[0].Type {
	case layers.DNSTypeTXT:
		for _, r := range z.Txt {
			if r.Host == host {
				dnsAnswer.TXTs = append(dnsAnswer.TXTs, []byte(r.Value))
			}
		}
	}

	replyMess.QR = true
	replyMess.OpCode = layers.DNSOpCodeNotify
	replyMess.AA = true
	replyMess.Answers = append(replyMess.Answers, dnsAnswer)
	replyMess.ANCount = uint16(len(replyMess.Answers))

	replyMess.ResponseCode = layers.DNSResponseCodeNoErr
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	err = replyMess.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}
	u.WriteTo(buf.Bytes(), clientAddr)
}
