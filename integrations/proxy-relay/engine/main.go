package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Entry struct {
	ID           int    `json:"id"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Host         string `json:"host"`
	UpstreamPort int    `json:"upstream_port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type Config struct {
	ClientUser     string  `json:"client_user"`
	ClientPassword string  `json:"client_password"`
	Revision       string  `json:"revision"`
	Entries        []Entry `json:"entries"`
}

func (e Entry) Valid() bool {
	return e.Port > 0 && e.Port < 65536 && e.UpstreamPort > 0 && e.UpstreamPort < 65536 && e.Host != "" && (e.Protocol == "socks5" || e.Protocol == "http")
}

func validBasic(value, username, password string) bool {
	if !strings.HasPrefix(value, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "Basic "))
	return err == nil && string(decoded) == username+":"+password
}

type running struct {
	ln    net.Listener
	state *listenerState
}

type listenerState struct {
	mu             sync.RWMutex
	entry          Entry
	clientUser     string
	clientPassword string
}

func (s *listenerState) update(entry Entry, user, password string) {
	s.mu.Lock()
	s.entry, s.clientUser, s.clientPassword = entry, user, password
	s.mu.Unlock()
}

func (s *listenerState) snapshot() (Entry, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entry, s.clientUser, s.clientPassword
}

var mu sync.Mutex
var active = map[int]running{}

func load(path string) (Config, error) {
	var config Config
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(data, &config)
	return config, err
}

func reconcile(path string) error {
	config, err := load(path)
	if err != nil {
		return err
	}
	wanted := map[int]Entry{}
	for _, entry := range config.Entries {
		if !entry.Valid() {
			return fmt.Errorf("invalid relay entry on port %d", entry.Port)
		}
		if _, exists := wanted[entry.Port]; exists {
			return fmt.Errorf("duplicate relay listener port %d", entry.Port)
		}
		wanted[entry.Port] = entry
	}

	mu.Lock()
	var failures []string
	for port, listener := range active {
		if _, ok := wanted[port]; !ok {
			listener.ln.Close()
			delete(active, port)
		}
	}
	for port, entry := range wanted {
		if listener, ok := active[port]; ok {
			listener.state.update(entry, config.ClientUser, config.ClientPassword)
			continue
		}
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("listen %d: %v", port, err)
			failures = append(failures, fmt.Sprintf("listen %d: %v", port, err))
			continue
		}
		state := &listenerState{entry: entry, clientUser: config.ClientUser, clientPassword: config.ClientPassword}
		active[port] = running{ln: listener, state: state}
		go serve(listener, state)
		log.Printf("listening %d %s", port, entry.Protocol)
	}
	mu.Unlock()
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return writeLoadedRevision(path, config.Revision)
}

func writeLoadedRevision(path, revision string) error {
	temporary := path + ".loaded.tmp"
	loaded := path + ".loaded"
	if err := os.WriteFile(temporary, []byte(revision), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, loaded)
}

func serve(listener net.Listener, state *listenerState) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		entry, username, password := state.snapshot()
		go func() {
			defer client.Close()
			if entry.Protocol == "socks5" {
				handleClientSocks(client, entry, username, password)
			} else {
				handleClientHTTP(client, entry, username, password)
			}
		}()
	}
}

func dialUpstream(entry Entry) (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(entry.Host, strconv.Itoa(entry.UpstreamPort)), 10*time.Second)
}

func socksConnect(entry Entry, host string, port int) (net.Conn, error) {
	conn, err := dialUpstream(entry)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(conn, response); err != nil || response[1] != 2 {
		return fail(errors.New("socks auth method"))
	}
	username, password := []byte(entry.Username), []byte(entry.Password)
	auth := append(append([]byte{1, byte(len(username))}, username...), append([]byte{byte(len(password))}, password...)...)
	if _, err = conn.Write(auth); err != nil {
		return fail(err)
	}
	if _, err = io.ReadFull(conn, response); err != nil || response[1] != 0 {
		return fail(errors.New("socks auth"))
	}
	name := []byte(host)
	request := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)
	request = append(request, byte(port>>8), byte(port))
	if _, err = conn.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil || header[1] != 0 {
		return fail(errors.New("socks connect"))
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			return fail(err)
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	}
	if _, err = io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return fail(err)
	}
	return conn, nil
}

func handleClientSocks(conn net.Conn, entry Entry, username, password string) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 1 {
		return
	}
	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return
	}
	pass := make([]byte, int(header[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return
	}
	if string(user) != username || string(pass) != password {
		conn.Write([]byte{1, 1})
		return
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return
	}
	host, port, err := readSocksTarget(conn)
	if err != nil {
		return
	}
	upstream, err := socksConnect(entry, host, port)
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	pipe(conn, upstream)
}

func readSocksTarget(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", 0, err
		}
		host = net.IP(address).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", 0, err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", 0, err
		}
		host = string(address)
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", 0, err
		}
		host = net.IP(address).String()
	default:
		return "", 0, errors.New("atyp")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBytes)), nil
}

func handleClientHTTP(conn net.Conn, entry Entry, username, password string) {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if !validBasic(request.Header.Get("Proxy-Authorization"), username, password) {
		fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=relay\r\nContent-Length: 0\r\n\r\n")
		return
	}
	upstream, err := dialUpstream(entry)
	if err != nil {
		return
	}
	defer upstream.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(entry.Username + ":" + entry.Password))
	request.Header.Set("Proxy-Authorization", "Basic "+auth)
	if request.Method == "CONNECT" {
		fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", request.Host, request.Host, auth)
		response, err := http.ReadResponse(bufio.NewReader(upstream), request)
		if err != nil || response.StatusCode/100 != 2 {
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipe(conn, upstream)
		return
	}
	request.RequestURI = request.URL.String()
	if err = request.WriteProxy(upstream); err != nil {
		return
	}
	pipe(conn, upstream)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

func main() {
	path := "/opt/proxy-relay/relay.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if err := reconcile(path); err != nil {
		log.Printf("initial reconcile: %v", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for received := range signals {
		if received == syscall.SIGHUP {
			if err := reconcile(path); err != nil {
				log.Printf("reconcile: %v", err)
			}
		} else {
			return
		}
	}
}
