package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/core/shared"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"api/pkg/adapters"
	gen "api/pkg/gen"
)

const versionMethod = "/api.ApiService/Version"

// counting is the console's API with its handler runs counted.
type counting struct {
	gen.UnimplementedApiServiceServer
	ran atomic.Int64
}

func (c *counting) Version(context.Context, *gen.VersionRequest) (*gen.VersionResponse, error) {
	c.ran.Add(1)
	return &gen.VersionResponse{Version: "0.1.0"}, nil
}

// served is the console's generated server, both listeners, with its
// verifier installed exactly as answerFromTheStamp installs it, over keys
// that publish the hop's admission key and nothing configured beside them.
type served struct {
	api           *counting
	grpc, connect string // listener addresses
	md            metadata.MD
	retainedUntil time.Time // the admission's expiry plus the clock allowance
}

func serve(t *testing.T) *served {
	t.Helper()
	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	authority := hoptest.New(t).PublishHop("console-hop")
	token := authority.IssueSingleUse(t, "console")
	s := &served{api: &counting{}, md: hoptest.Forward(t, token, "console-hop", versionMethod)}
	// A one-second admission, so its window closes inside the test.
	issued := time.Now()
	proof, err := hoptest.Signer("console-hop").Sign(token, versionMethod, "console", issued, issued.Add(time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	s.md.Set(hop.ProofKey, proof)
	call, err := stamp.Check(s.md, hoptest.PublicKey("console-hop"), versionMethod, "console", issued)
	if err != nil {
		t.Fatal(err)
	}
	s.retainedUntil = time.Unix(call.Expires+int64(stamp.Skew/time.Second), 0)

	verifier, err := hop.NewVerifier(context.Background(), authority, "console", hoptest.Replay())
	if err != nil {
		t.Fatal(err)
	}
	grpcPort, connectPort := freePort(t), freePort(t)
	config := &adapters.Configuration{EndpointGrpcPort: grpcPort, EndpointConnectPort: shared.Pointer(connectPort)}
	install(config, verifier)
	config.Service = s.api
	server, err := adapters.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Start(ctx) }()
	t.Cleanup(func() { cancel(); server.Stop() })
	s.grpc, s.connect = fmt.Sprintf("127.0.0.1:%d", grpcPort), fmt.Sprintf("127.0.0.1:%d", connectPort)
	for _, address := range []string{s.grpc, s.connect} {
		for deadline := time.Now().Add(5 * time.Second); ; {
			if conn, err := net.Dial("tcp", address); err == nil {
				_ = conn.Close()
				break
			} else if time.Now().After(deadline) {
				t.Fatalf("%s never listened: %v", address, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return s
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// Review r3 M1: the hop routes the console's gRPC to its Connect listener,
// which hands each call to the gRPC server through ServeHTTP, where no tap
// handle runs, so a genuine call whose body arrived after the admission's
// window was refused as stamp_window. The verifier's stats handler judges the
// window when the call reaches the server, on that listener as on the gRPC
// one: a genuine call whose body arrives late is admitted, and its handler
// runs once.
func TestALateBodyIsJudgedAtArrivalOnBothListeners(t *testing.T) {
	for _, listener := range []string{"grpc", "connect"} {
		t.Run(listener, func(t *testing.T) {
			s := serve(t)
			address := s.grpc
			if listener == "connect" {
				address = s.connect
			}
			conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			stream, err := conn.NewStream(metadata.NewOutgoingContext(ctx, s.md.Copy()), &grpc.StreamDesc{}, versionMethod)
			if err != nil {
				t.Fatal(err)
			}
			// The headers are sent now; the body only once the window has closed.
			time.Sleep(time.Until(s.retainedUntil) + 300*time.Millisecond)
			if err := stream.SendMsg(&gen.VersionRequest{}); err != nil {
				t.Fatal(err)
			}
			if err := stream.CloseSend(); err != nil {
				t.Fatal(err)
			}
			if err := stream.RecvMsg(&gen.VersionResponse{}); err != nil {
				t.Fatalf("a genuine call whose body arrived late was refused: %v", err)
			}
			if got := s.api.ran.Load(); got != 1 {
				t.Fatalf("the handler ran %d times", got)
			}
		})
	}
}

// The same over the Connect protocol, as the hop's HTTP face forwards a
// Connect call: the unary body arrives after the window has closed.
func TestALateConnectBodyIsJudgedAtArrival(t *testing.T) {
	s := serve(t)
	body, _ := proto.Marshal(&gen.VersionRequest{})
	reader, writer := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, "http://"+s.connect+versionMethod, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/proto")
	request.Header.Set("Connect-Protocol-Version", "1")
	for key, values := range s.md {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	go func() {
		time.Sleep(time.Until(s.retainedUntil) + 300*time.Millisecond)
		_, _ = io.Copy(writer, bytes.NewReader(body))
		_ = writer.Close()
	}()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.Contains(string(answer), "stamp_") {
		t.Fatalf("a genuine Connect call whose body arrived late was refused: %d %s", response.StatusCode, answer)
	}
	if got := s.api.ran.Load(); got != 1 {
		t.Fatalf("the handler ran %d times", got)
	}
}

// One admission delivered on both listeners at once runs the handler once:
// every other delivery meets the reservation made when the first arrived.
func TestOneAdmissionOnBothListenersRunsOnce(t *testing.T) {
	s := serve(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var admitted atomic.Int64
	done := make(chan struct{})
	deliveries := 0
	for _, address := range []string{s.grpc, s.connect} {
		conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for range 4 {
			deliveries++
			go func() {
				defer func() { done <- struct{}{} }()
				var answer gen.VersionResponse
				if conn.Invoke(metadata.NewOutgoingContext(ctx, s.md.Copy()), versionMethod, &gen.VersionRequest{}, &answer) == nil {
					admitted.Add(1)
				}
			}()
		}
	}
	for range deliveries {
		<-done
	}
	if admitted.Load() != 1 || s.api.ran.Load() != 1 {
		t.Fatalf("SECURITY: %d of %d deliveries admitted, handler ran %d times", admitted.Load(), deliveries, s.api.ran.Load())
	}
}
