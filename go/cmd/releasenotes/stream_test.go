/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sse assembles a stream from already-formed lines, so a test can express the
// exact bytes on the wire (blank lines, comments, a missing terminator).
func sse(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func delta(content string) string {
	return `data: {"choices":[{"delta":{"content":` + jsonString(content) + `}}]}`
}

// stop is the terminal chunk. Every fixture that expects to SUCCEED must carry
// one: finish_reason is the completion signal, and a real OpenAI-shaped stream
// always sends it. A fixture that omits it is testing a truncated stream,
// whether or not its author meant to.
const stop = `data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`

func jsonString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func readAll(t *testing.T, stream string) (*draftResult, error) {
	t.Helper()
	res := &draftResult{}
	return res, res.readSSE(strings.NewReader(stream))
}

// The keepalive comment is the entire reason this call streams: the node emits
// it through a long prefill so an intermediary can't reset a byte-silent
// connection. This pins that a stream carrying them still parses and that they
// never become content — NOT that the explicit comment branch is what drops
// them (the switch's default arm would too; the branch is there to say why they
// arrive at all). An empty `data:` field is here for the same reason: some
// gateways send that instead of a comment, and it used to fail the whole
// already-billed stream on `unexpected end of JSON input`.
func TestReadSSE_KeepalivesDoNotCorruptTheStream(t *testing.T) {
	res, err := readAll(t, sse(
		": zs-keepalive", "",
		"data:", "",
		": zs-keepalive", "",
		delta("hello"), "",
		stop, "",
		"data: [DONE]", "",
	))
	if err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	if res.content != "hello" {
		t.Errorf("content = %q, want %q", res.content, "hello")
	}
}

func TestReadSSE_ConcatenatesDeltasInOrder(t *testing.T) {
	res, err := readAll(t, sse(
		delta("### High"), "",
		delta("lights\n\n"), "",
		delta("- one"), "",
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`, "",
		"data: [DONE]", "",
	))
	if err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	if want := "### Highlights\n\n- one"; res.content != want {
		t.Errorf("content = %q, want %q", res.content, want)
	}
	if res.finish != "stop" {
		t.Errorf("finish = %q, want %q", res.finish, "stop")
	}
}

// SPEC §5.3: a mid-stream failure arrives as `data: {"error": …}` followed by a
// plaintext [DONE]. Treating that as content would publish an error envelope as
// the release notes.
func TestReadSSE_InBandErrorFrameIsAnError(t *testing.T) {
	res, err := readAll(t, sse(
		delta("partial answer"), "",
		`data: {"error":{"message":"upstream exploded","code":"server_error"}}`, "",
		"data: [DONE]", "",
	))
	if err == nil {
		t.Fatal("readSSE returned nil error on an in-band error frame")
	}
	if !strings.Contains(err.Error(), "upstream exploded") {
		t.Errorf("error = %v, want it to carry the upstream message", err)
	}
	// The partial content is still handed back so -debug-dir can show it.
	if res.content != "partial answer" {
		t.Errorf("content = %q, want the partial content preserved", res.content)
	}
}

// The truncation guard in draft() reads res.finish, so "length" has to survive
// the stream. A truncated draft published to a release page is the failure this
// whole path exists to prevent.
func TestReadSSE_PropagatesFinishReasonLength(t *testing.T) {
	res, err := readAll(t, sse(
		delta("cut off here"), "",
		`data: {"choices":[{"delta":{},"finish_reason":"length"}]}`, "",
		"data: [DONE]", "",
	))
	if err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	if res.finish != "length" {
		t.Errorf("finish = %q, want %q", res.finish, "length")
	}
}

// Usage arrives in two shapes and BOTH must be read. An empty choices list is
// a usage-only chunk; a GLM-shaped backend instead bundles usage onto the final
// content chunk. The counts here are deliberately different per subtest — with
// one shared number a reader that handles only one shape still satisfies the
// assertion, which is how a test like this passes while being blind to the very
// case its name claims.
func TestReadSSE_ReadsUsageInBothShapes(t *testing.T) {
	for _, tc := range []struct {
		name             string
		chunk            string
		prompt, complete int
	}{
		{
			name:   "usage-only chunk (empty choices)",
			chunk:  `data: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":22}}`,
			prompt: 11, complete: 22,
		},
		{
			name:   "bundled onto the final content chunk (GLM shape)",
			chunk:  `data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":33,"completion_tokens":44}}`,
			prompt: 33, complete: 44,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := readAll(t, sse(delta("body"), "", tc.chunk, "", stop, "", "data: [DONE]", ""))
			if err != nil {
				t.Fatalf("readSSE: %v", err)
			}
			if res.content != "body" {
				t.Errorf("content = %q, want %q", res.content, "body")
			}
			if res.prompt != tc.prompt || res.completion != tc.complete {
				t.Errorf("usage = %d/%d, want %d/%d", res.prompt, res.completion, tc.prompt, tc.complete)
			}
		})
	}
}

// The bufio.Scanner regression. Scanner caps a line at 64KB and returns
// bufio.ErrTooLong; ReadBytes grows. A single delta frame genuinely exceeds
// that on a long generation, so this is the difference between a working run
// and a truncated one.
func TestReadSSE_HandlesLineLongerThan64KB(t *testing.T) {
	huge := strings.Repeat("x", 200<<10)
	res, err := readAll(t, sse(delta(huge), "", stop, "", "data: [DONE]", ""))
	if err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	// Compared by value, not by length: a length check passes on any
	// length-preserving corruption, which is most of them.
	if res.content != huge {
		t.Errorf("content did not round-trip (got %d bytes, want %d)", len(res.content), len(huge))
	}
}

// finish_reason is the completion signal, and BOTH exits enforce it.
//
// The "[DONE] with no finish_reason" case is the one worth having: [DONE] is a
// stream sentinel, not a claim that the model finished, so trusting it alone
// publishes a cut-off draft that looks perfectly well-formed. That is this
// tool's worst failure mode, and it is invisible without this case — the
// bare-EOF case alone passes against an implementation that trusts [DONE].
func TestReadSSE_AnswerWithoutAFinishReasonIsRejected(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"connection closed mid-answer", sse(delta("half an answ"), "")},
		{"[DONE] with no finish_reason", sse(delta("half an answ"), "", "data: [DONE]", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := readAll(t, tc.stream)
			if err == nil {
				t.Fatal("readSSE accepted an answer with no finish_reason")
			}
			if !strings.Contains(err.Error(), "cut short") {
				t.Errorf("error = %v, want it to say the response was cut short", err)
			}
			if res.content != "half an answ" {
				t.Errorf("content = %q, want the partial preserved for -debug-dir", res.content)
			}
		})
	}
}

// The other half of that rule: a backend that closes on its terminal chunk
// instead of sending [DONE] has still delivered a complete answer, and must not
// be rejected as truncated.
func TestReadSSE_FinishReasonWithoutDoneIsComplete(t *testing.T) {
	res, err := readAll(t, sse(delta("whole answer"), "", stop, ""))
	if err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	if res.content != "whole answer" {
		t.Errorf("content = %q", res.content)
	}
}

// Backends disagree on the spelling and the node normalizes one to the other,
// so which arrives depends on where in the chain that happened. Missing both
// would turn "the model only reasoned" into the opaque "empty content".
func TestReadSSE_ReadsBothReasoningSpellings(t *testing.T) {
	for _, field := range []string{"reasoning", "reasoning_content"} {
		res, err := readAll(t, sse(
			`data: {"choices":[{"delta":{"`+field+`":"thinking"}}]}`, "",
			stop, "",
			"data: [DONE]", "",
		))
		if err != nil {
			t.Fatalf("%s: readSSE: %v", field, err)
		}
		if res.reasoning != "thinking" {
			t.Errorf("%s: reasoning = %q, want %q", field, res.reasoning, "thinking")
		}
	}
}

// ---------------------------------------------------------------------------
// retry
// ---------------------------------------------------------------------------

func testOptions(url string) *options {
	return &options{baseURL: url, model: "test-model", timeout: 10 * time.Second}
}

// quietLogger swallows the "http: panic serving" line the deliberate
// ErrAbortHandler below would otherwise print into the test output.
func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// fastBackoff keeps a REGRESSION fast. These tests pass by not retrying, so the
// sleep only costs anything when one of them fails — which is exactly when you
// want the answer quickly.
func fastBackoff(t *testing.T) {
	t.Helper()
	prev := retryBackoff
	retryBackoff = time.Millisecond
	t.Cleanup(func() { retryBackoff = prev })
}

// The money test. Once a 2xx comes back the reserve leg has already opened an
// escrow ticket, so a mid-stream failure has been billed regardless of how
// little arrived. A second attempt buys a second ticket, not a better answer.
func TestPostWithRetry_DoesNotRetryAfterA2xx(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, delta("started answering")+"\n\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // sever the connection mid-stream
	}))
	srv.Config.ErrorLog = quietLogger()
	defer srv.Close()

	_, err := postWithRetry(context.Background(), testOptions(srv.URL), []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error from a severed stream")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d requests, want 1 — a post-2xx failure is already billed", got)
	}
}

// A gateway timeout is the failure that motivated streaming in the first place,
// and it is NOT free: the proxy forwards it from beyond a reserve that already
// succeeded. Re-sending it was costing a second ticket per run.
func TestPostWithRetry_DoesNotRetryAGatewayHTMLError(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusGatewayTimeout)
		fmt.Fprint(w, "<html><head><title>504 Gateway Time-out</title></head><body>…</body></html>")
	}))
	defer srv.Close()

	_, err := postWithRetry(context.Background(), testOptions(srv.URL), []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error from a 504")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d requests, want 1 — a forwarded 504 is already billed", got)
	}
	// summarizeErrorBody must still pull the one useful line out of the page.
	if !strings.Contains(err.Error(), "504 Gateway Time-out") {
		t.Errorf("error = %v, want the HTML title surfaced", err)
	}
}

// The retry has to stay alive for the classes that genuinely abort before a
// ticket opens, or the fix above quietly removes it altogether.
func TestPostWithRetry_RetriesAPreReserveRateLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":{"message":"slow down","type":"rate_limit"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, delta("second time lucky")+"\n\n"+stop+"\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	fastBackoff(t)

	res, err := postWithRetry(context.Background(), testOptions(srv.URL), []byte(`{}`))
	if err != nil {
		t.Fatalf("postWithRetry: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d requests, want 2", got)
	}
	if res.content != "second time lucky" {
		t.Errorf("content = %q", res.content)
	}
}

// A transport error is NOT automatically free, and the two halves of that rule
// need separate tests or one covers for the other.
//
// This half: the server accepted the whole request and then dropped the
// connection. http.Client.Do reports an error, but the body WAS delivered — on
// a zs-proxy that means the reserve leg ran and the escrow ticket is open, so
// re-asking buys a second ticket.
//
// It must not be written as a timeout. A timeout is stopped by the shared
// -timeout deadline anyway, so such a test passes whether or not dialFailed
// exists — measured: mutating dialFailed(err) to a bare `true` left the whole
// suite green against the timeout version of this test.
func TestPostWithRetry_DoesNotRetryAfterTheRequestWasDelivered(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body) // the request is fully delivered...
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Close() // ...and then the connection drops, with no response.
	}))
	defer srv.Close()

	if _, err := postWithRetry(context.Background(), testOptions(srv.URL), []byte(`{}`)); err == nil {
		t.Fatal("expected a transport error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d requests, want 1 — the body was delivered, so the ticket is open", got)
	}
}

// The other half: a genuine dial failure never reached a server, so nothing was
// reserved and the retry is free. Without this, dialFailed could be a constant
// false and the suite above would still pass — which would quietly delete the
// last useful retry the tool has.
func TestPostWithRetry_RetriesADialFailure(t *testing.T) {
	// A port nothing is listening on: httptest hands us a real one, then we
	// close it so the connection is refused rather than merely slow.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	// The backoff sleep IS the observable: a refused connection on loopback
	// returns in ~1ms, so only a real second attempt can push elapsed past it.
	// Asserting dialFailed(err) directly would not do — measured, that passes
	// against a `post` that ignores dialFailed entirely and never retries.
	prev := retryBackoff
	retryBackoff = 80 * time.Millisecond
	t.Cleanup(func() { retryBackoff = prev })

	started := time.Now()
	_, err := postWithRetry(context.Background(), testOptions(dead), []byte(`{}`))
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("expected a dial error")
	}
	if !dialFailed(err) {
		t.Fatalf("dialFailed(%v) = false — this test is not exercising a dial failure", err)
	}
	if elapsed < retryBackoff {
		t.Errorf("returned in %s, under the %s backoff — it never retried, so the tool's "+
			"one genuinely free retry is gone", elapsed.Round(time.Millisecond), retryBackoff)
	}
}

// -timeout bounds the whole call, not each attempt. Per-attempt it is silently
// a 2x budget: the default is 10 minutes, so a regression here means a run that
// should give up at 10 hangs for 20 and spends two tickets doing it.
func TestPostWithRetry_TimeoutCoversBothAttempts(t *testing.T) {
	fastBackoff(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests) // retryable, so it will re-ask
		fmt.Fprint(w, `{"error":{"message":"slow down"}}`)
	}))
	defer srv.Close()

	o := testOptions(srv.URL)
	o.timeout = 120 * time.Millisecond
	retryBackoff = 400 * time.Millisecond // outlasts the budget on purpose

	started := time.Now()
	if _, err := postWithRetry(context.Background(), o, []byte(`{}`)); err == nil {
		t.Fatal("expected an error")
	}
	// The backoff select must observe the shared deadline and abandon the
	// retry. A per-attempt deadline cannot, because it lives on a context the
	// select never sees.
	if elapsed := time.Since(started); elapsed > 350*time.Millisecond {
		t.Errorf("took %s — the retry outlived the -timeout budget", elapsed.Round(time.Millisecond))
	}
}

// An endpoint that ignores "stream": true returns a COMPLETE answer that the
// SSE reader cannot parse. Reporting that as "cut short" sends the releaser
// looking for a truncation that never happened, and costs a ticket to find out.
func TestPost_DeStreamedResponseIsDiagnosedByName(t *testing.T) {
	fastBackoff(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"a whole answer"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	_, err := postWithRetry(context.Background(), testOptions(srv.URL), []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error for a non-SSE 2xx")
	}
	if !strings.Contains(err.Error(), `ignored "stream": true`) {
		t.Errorf("error = %v, want it to name the de-streamed response", err)
	}
	if strings.Contains(err.Error(), "cut short") {
		t.Errorf("error = %v, must not report a complete answer as truncated", err)
	}
}

// The last gate before bytes reach a file that gets published verbatim.
func TestValidateDraft(t *testing.T) {
	// draftResult holds an atomic counter, so it cannot be a table value.
	result := func(content, reasoning, finish string) *draftResult {
		return &draftResult{content: content, reasoning: reasoning, finish: finish}
	}
	for _, tc := range []struct {
		name        string
		res         *draftResult
		wantErr     string
		wantContent string
	}{
		{
			name:    "output cap hit",
			res:     result("### Highlights\n- half a th", "", "length"),
			wantErr: "output cap",
		},
		{
			name:    "reasoning but no answer",
			res:     result("", "let me think", "stop"),
			wantErr: "only reasoning content",
		},
		{
			name:    "nothing at all",
			res:     result("", "", "stop"),
			wantErr: "empty content",
		},
		{
			name:        "a real draft",
			res:         result("\n### Highlights\n- a thing\n", "", "stop"),
			wantContent: "### Highlights\n- a thing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateDraft(tc.res)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("validateDraft returned %q, want an error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDraft: %v", err)
			}
			if got != tc.wantContent {
				t.Errorf("content = %q, want %q", got, tc.wantContent)
			}
		})
	}
}
