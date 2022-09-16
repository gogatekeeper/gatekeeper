package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/plugins"
	opaserver "github.com/open-policy-agent/opa/server"
	opastorage "github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

type OpaInput struct {
	Body       string              `json:"body"`
	Headers    map[string][]string `json:"headers"`
	Host       string              `json:"host"`
	Proto      string              `json:"protocol"`
	Path       string              `json:"path"`
	RemoteAddr string              `json:"remote_addr"`
	Method     string              `json:"method"`
	UserAgent  string              `json:"user_agent"`
}

type OpaAuthzRequest struct {
	Input *OpaInput `json:"input"`
}

type OpaAuthzResponse struct {
	Result bool `json:"result"`
}

var _ Provider = (*OpaAuthorizationProvider)(nil)

type OpaAuthorizationProvider struct {
	timeout  time.Duration
	authzURL url.URL
	req      *http.Request
}

func NewOpaAuthorizationProvider(
	timeout time.Duration,
	authzURL url.URL,
	req *http.Request,
) Provider {
	return &OpaAuthorizationProvider{
		timeout:  timeout,
		authzURL: authzURL,
		req:      req,
	}
}

func (p *OpaAuthorizationProvider) Authorize() (AuthzDecision, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	reqBody, err := ioutil.ReadAll(p.req.Body)

	if err != nil {
		return DeniedAuthz, err
	}

	opaReq := &OpaAuthzRequest{Input: &OpaInput{}}
	opaReq.Input.Body = string(reqBody)
	opaReq.Input.Headers = p.req.Header
	opaReq.Input.Host = p.req.Host
	opaReq.Input.Method = p.req.Method
	opaReq.Input.Path = p.req.URL.Path
	opaReq.Input.Proto = p.req.Proto
	opaReq.Input.RemoteAddr = p.req.RemoteAddr
	opaReq.Input.UserAgent = p.req.UserAgent()

	opaReqBody, err := json.Marshal(opaReq)

	if err != nil {
		return DeniedAuthz, err
	}

	httpReq, err := http.NewRequest(
		http.MethodPost,
		p.authzURL.String(),
		bytes.NewReader(opaReqBody),
	)

	if err != nil {
		return DeniedAuthz, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = httpReq.WithContext(ctx)

	client := &http.Client{}
	opaResp := &OpaAuthzResponse{}

	resp, err := client.Do(httpReq)

	if err != nil {
		return DeniedAuthz, err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return DeniedAuthz, err
	}

	err = json.Unmarshal(body, opaResp)

	if err != nil {
		return DeniedAuthz, err
	}

	defer resp.Body.Close()

	if opaResp.Result && resp.StatusCode == http.StatusOK {
		return AllowedAuthz, nil
	}

	var msg error

	if resp.StatusCode != http.StatusOK {
		msg = fmt.Errorf(
			"authz response: %s, status: %d",
			body,
			resp.StatusCode,
		)
	}

	return DeniedAuthz, msg
}

//nolint:cyclop
func StartOpaServer(
	ctx context.Context,
	t *testing.T,
	authzPolicy string,
) *opaserver.Server {
	t.Helper()

	store := inmem.New()
	server := opaserver.New().
		WithAddresses([]string{":0"}).
		WithStore(store)

	mgr, err := plugins.New([]byte{}, "test", store)

	if err != nil {
		t.Fatal(err)
	}

	server = server.WithManager(mgr)

	if err = mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}

	txn := opastorage.NewTransactionOrDie(ctx, store, opastorage.WriteParams)
	err = store.UpsertPolicy(ctx, txn, "test", []byte(authzPolicy))

	if err != nil {
		t.Fatal(err)
	}

	if err = store.Commit(ctx, txn); err != nil {
		t.Fatal(err)
	}

	server, err = server.Init(ctx)

	if err != nil {
		t.Fatal(err)
	}

	loops, err := server.Listeners()
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	errc := make(chan error)
	for _, loop := range loops {
		go func(serverLoop func() error) {
			errc <- serverLoop()
		}(loop)
	}

	var addrs []string
	checkRounds := 0

	for {
		addrs = server.Addrs()

		if len(addrs) > 0 {
			break
		}

		if checkRounds == 5 {
			t.Fatalf("opa didn't came up after %d seconds", checkRounds)
		}

		checkRounds++
		time.Sleep(time.Second)
	}

	return server
}
