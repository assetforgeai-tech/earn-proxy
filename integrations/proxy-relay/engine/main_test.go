package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func startFakeHTTPProxy(t *testing.T) (int, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	requests := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				for {
					header, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(header) == "" {
						break
					}
				}
				requests <- strings.TrimSpace(line)
				fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
				io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, requests
}

func writeConfig(t *testing.T, path, revision string, entry Entry) {
	t.Helper()
	data, err := json.Marshal(Config{
		ClientUser:     "client",
		ClientPassword: "secret",
		Revision:       revision,
		Entries:        []Entry{entry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func requestViaRelay(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte("client:secret"))
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if strings.TrimSpace(status) != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("unexpected relay response: %q", status)
	}
}

func TestReconcileUpdatesUpstreamWithoutReplacingListener(t *testing.T) {
	oldPort, oldRequests := startFakeHTTPProxy(t)
	newPort, newRequests := startFakeHTTPProxy(t)
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	configPath := t.TempDir() + "/relay.json"

	mu.Lock()
	active = map[int]running{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		if listener, ok := active[listenPort]; ok {
			listener.ln.Close()
			delete(active, listenPort)
		}
		mu.Unlock()
	})

	writeConfig(t, configPath, "before", Entry{Port: listenPort, Protocol: "http", Host: "127.0.0.1", UpstreamPort: oldPort, Username: "u", Password: "p"})
	if err := reconcile(configPath); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	originalListener := active[listenPort].ln
	mu.Unlock()
	requestViaRelay(t, listenPort)
	select {
	case <-oldRequests:
	case <-time.After(time.Second):
		t.Fatal("initial request did not reach the original upstream")
	}

	writeConfig(t, configPath, "after", Entry{Port: listenPort, Protocol: "http", Host: "127.0.0.1", UpstreamPort: newPort, Username: "u2", Password: "p2"})
	if err := reconcile(configPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := os.ReadFile(configPath + ".loaded")
	if err != nil || string(loaded) != "after" {
		t.Fatalf("reload acknowledgement not updated: %q, %v", loaded, err)
	}
	mu.Lock()
	currentListener := active[listenPort].ln
	mu.Unlock()
	if currentListener != originalListener {
		t.Fatal("reconcile replaced the client listener instead of keeping its port open")
	}
	requestViaRelay(t, listenPort)
	select {
	case <-newRequests:
	case <-oldRequests:
		t.Fatal("new client connection still used the previous upstream entry")
	case <-time.After(time.Second):
		t.Fatal("reconciled request did not reach either upstream")
	}
}
