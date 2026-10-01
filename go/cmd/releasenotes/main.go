/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command releasenotes drafts a PUBLIC, user-facing RELEASE_NOTES.md from the
// commits since the previous tag, using a model on a RUNNING zs-proxy.
//
// It is the `make release-notes` implementation for both zs-proxy and zs-node
// (their source repos are separate, so this shared copy lives in the protocol
// module they both already depend on — `go.work` makes the workspace copy
// authoritative on a dev machine, which is the only place `make release` runs).
//
//	cd proxy && go run github.com/TxnLab/zerosignal/go/cmd/releasenotes -product zs-proxy
//	cd node  && go run github.com/TxnLab/zerosignal/go/cmd/releasenotes -product zs-node
//
// The source repos are PRIVATE and the output is published verbatim to a public
// GitHub release body and a Discord embed, so publish-safety is the governing
// constraint: commit hashes, author names, branch names, and changed file paths
// are never sent to the model at all, the prompt forbids emitting internals, and
// the result is scanned for leaks (locally, against data the model never saw)
// before it is written. It is still a model — the output is a DRAFT for review.
//
// This file MUST stay stdlib-only. The protocol module is a real dependency of
// both zs-proxy and zs-node, so a third-party import here lands in both of their
// module graphs for a tool neither of them ships.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// Records and fields inside the assembled payload. The unbounded field
	// (the commit body, %B) is always LAST, so a stray separator can only ever
	// appear in the fixed-width date or in the subject.
	recSep = "\x1e"
	fldSep = "\x1f"

	// bodyCapFloor bounds the oversize ladder: bodies shrink, commits never
	// get dropped. A missing commit is a missing public release note.
	bodyCapFloor = 600

	// discordLines / discordBytes are what `make release` actually slices out
	// of the file for the Discord announce embed. Exceeding them doesn't fail,
	// it warns — the summary just gets cut mid-section in the embed.
	discordLines = 55
	discordBytes = 3500
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "release-notes: %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

type options struct {
	product    string
	baseURL    string
	model      string
	out        string
	repo       string
	from       string
	to         string
	timeout    time.Duration
	offline    bool
	dryRun     bool
	keepGoing  bool
	maxCommits int
	maxBody    int
	maxInput   int
	debugDir   string
	apiKey     string
}

func parseFlags() (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("releasenotes", flag.ContinueOnError)
	fs.StringVar(&o.product, "product", "", "product profile: zs-proxy or zs-node (selects the prompt's audience framing)")
	fs.StringVar(&o.baseURL, "url", envOr("ZS_RELEASE_NOTES_URL", "http://127.0.0.1:9376/v1"), "OpenAI-compatible base URL of a RUNNING zs-proxy")
	fs.StringVar(&o.model, "model", envOr("ZS_RELEASE_NOTES_MODEL", "grok-4.6"), "model to draft with")
	fs.StringVar(&o.out, "out", "RELEASE_NOTES.md", "file to write (left untouched if the run fails)")
	fs.StringVar(&o.repo, "repo", ".", "git repository to read commits from")
	fs.StringVar(&o.from, "from", "", "start of the commit range (default: the tag before -to)")
	fs.StringVar(&o.to, "to", "HEAD", "end of the commit range")
	fs.DurationVar(&o.timeout, "timeout", envDuration("ZS_RELEASE_NOTES_TIMEOUT", 10*time.Minute), "timeout for the drafting call")
	fs.BoolVar(&o.offline, "offline", false, "skip the model: emit deterministic commit-subject buckets (no spend)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "print the assembled prompt and exit (no spend)")
	fs.BoolVar(&o.keepGoing, "keep-going", false, "on a failed drafting call, write the -offline output instead of failing")
	fs.IntVar(&o.maxCommits, "max-commits", 250, "refuse ranges larger than this rather than silently dropping commits")
	fs.IntVar(&o.maxBody, "max-body", 6000, "per-commit message-body cap in bytes")
	fs.IntVar(&o.maxInput, "max-input", 300000, "total payload budget in bytes")
	fs.StringVar(&o.debugDir, "debug-dir", "", "write prompt.txt / request.json / response.sse / response.txt here")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: releasenotes -product <zs-proxy|zs-node> [flags]\n\n"+
			"Drafts a public, user-facing RELEASE_NOTES.md from the commits since the\n"+
			"previous tag, using a model on a running zs-proxy.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, err
	}
	o.apiKey = os.Getenv("ZS_RELEASE_NOTES_API_KEY")

	if o.product == "" {
		return nil, errors.New("-product is required (zs-proxy or zs-node)")
	}
	if o.maxBody < bodyCapFloor {
		return nil, fmt.Errorf("-max-body %d is below the %d-byte floor", o.maxBody, bodyCapFloor)
	}
	if o.maxCommits < 1 {
		return nil, errors.New("-max-commits must be at least 1")
	}
	return o, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

func run() error {
	o, err := parseFlags()
	if err != nil {
		return err
	}
	profile, err := profileFor(o.product)
	if err != nil {
		return err
	}

	g := &git{dir: o.repo}
	if err := g.check(); err != nil {
		return err
	}
	rng, err := g.resolveRange(o.from, o.to)
	if err != nil {
		return err
	}
	commits, err := g.commits(rng)
	if err != nil {
		return err
	}
	if len(commits) == 0 {
		return fmt.Errorf("no non-merge commits in %s — nothing to draft", rng)
	}
	if len(commits) > o.maxCommits {
		return fmt.Errorf("%d commits in %s exceeds -max-commits=%d — narrow -from, or raise the cap",
			len(commits), rng, o.maxCommits)
	}
	logf(">> range %s (%d commits)", rng, len(commits))

	// The deterministic path never touches the network, so it needs neither a
	// running proxy nor a funded wallet.
	if o.offline {
		notes, err := offlineNotes(g, rng)
		if err != nil {
			return err
		}
		return writeOut(o.out, notes, offlineBanner(o.out, rng, len(commits)))
	}

	payload, err := buildPayload(commits, o.maxBody, o.maxInput)
	if err != nil {
		return err
	}
	system := profile.systemPrompt()
	user := profile.userPrompt(len(commits), payload)

	if o.dryRun {
		fmt.Printf("======== SYSTEM ========\n%s\n\n======== USER ========\n%s\n", system, user)
		logf(">> dry run: %d commits, %d bytes of payload, would have called %q at %s",
			len(commits), len(payload), o.model, o.baseURL)
		return nil
	}
	if err := dumpDebug(o.debugDir, "prompt.txt", []byte(system+"\n\n----\n\n"+user)); err != nil {
		return err
	}

	body, err := draft(o, system, user)
	if err != nil {
		if !o.keepGoing {
			return err
		}
		logf("WARNING: drafting failed (%v)", err)
		logf("WARNING: -keep-going set — falling back to raw commit subjects. REVIEW BEFORE PUBLISHING.")
		notes, offErr := offlineNotes(g, rng)
		if offErr != nil {
			return err
		}
		return writeOut(o.out, notes, offlineBanner(o.out, rng, len(commits)))
	}

	notes := normalize(body)
	scanForLeaks(g, rng, notes)
	checkDiscordBudget(notes)

	return writeOut(o.out, notes, fmt.Sprintf(
		">> wrote %s (%s, %d commits, drafted by %s) — REVIEW/EDIT before 'make release' (it is published publicly).",
		o.out, rng, len(commits), o.model))
}

// writeOut writes the assembled body in one shot. Nothing before this point
// truncates the destination, so a failed run leaves the previous notes intact.
func writeOut(path, body, banner string) error {
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	logf("%s", banner)
	return nil
}

func offlineBanner(out, rng string, n int) string {
	return fmt.Sprintf(">> wrote %s (%s, %d commits, deterministic commit subjects — NOT curated) — REVIEW/EDIT before 'make release' (it is published publicly).",
		out, rng, n)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

type git struct{ dir string }

type commit struct {
	Date    string
	Subject string
	Body    string
}

func (g *git) run(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", g.dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

func (g *git) check() error {
	if _, err := g.run("rev-parse", "--git-dir"); err != nil {
		return fmt.Errorf("%s is not a git repository (use -repo)", g.dir)
	}
	return nil
}

// resolveRange reproduces the range the old awk target used. The `<to>^` in the
// describe is load-bearing: the documented release flow tags the release commit
// BEFORE drafting notes, so describing from the parent yields the PREVIOUS tag
// rather than the one just created. No previous tag (root, or an untagged repo)
// degrades to the full history.
func (g *git) resolveRange(from, to string) (string, error) {
	if to == "" {
		to = "HEAD"
	}
	if from == "" {
		out, err := g.run("describe", "--tags", "--abbrev=0", "--match", "v*", to+"^")
		if err == nil {
			from = strings.TrimSpace(out)
		}
	}
	if from == "" {
		return to, nil
	}
	return from + ".." + to, nil
}

// commits reads the range oldest-first with each commit's FULL message body.
// Chronological order is deliberate (the old target was newest-first): it lets
// the model see that a later commit corrected an earlier one in the same window
// and fold them into a single bullet.
func (g *git) commits(rng string) ([]commit, error) {
	out, err := g.run("log", "--reverse", "--no-merges", "--date=short",
		"--pretty=format:"+recSep+"%ad"+fldSep+"%s"+fldSep+"%B", rng)
	if err != nil {
		return nil, err
	}
	var commits []commit
	for _, rec := range strings.Split(out, recSep) {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		fields := strings.SplitN(rec, fldSep, 3)
		if len(fields) < 3 {
			continue
		}
		commits = append(commits, commit{
			Date:    strings.TrimSpace(fields[0]),
			Subject: sanitize(strings.TrimSpace(fields[1])),
			Body:    cleanBody(fields[2]),
		})
	}
	return commits, nil
}

// subjectsNewestFirst backs the -offline path, which must stay byte-identical
// to the awk one-liner it replaced (so the regression check is a plain diff).
func (g *git) subjectsNewestFirst(rng string) ([]string, error) {
	out, err := g.run("log", "--no-merges", "--pretty=tformat:%s", rng)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines, nil
}

var trailerRe = regexp.MustCompile(`(?i)^(co-authored-by|signed-off-by|reviewed-by|change-id|acked-by|tested-by)\s*:`)

// cleanBody strips maintainer trailers (a commit's Co-Authored-By is both noise
// and a name we deliberately never send) and normalizes whitespace.
func cleanBody(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if trailerRe.MatchString(strings.TrimSpace(line)) {
			continue
		}
		kept = append(kept, strings.TrimRight(line, " \t"))
	}
	return sanitize(collapseBlankRuns(strings.TrimSpace(strings.Join(kept, "\n"))))
}

// sanitize makes it structurally impossible for commit text to close one of the
// payload's own tags. Commit prose does occasionally contain markup.
func sanitize(s string) string { return strings.ReplaceAll(s, "</", "< /") }

func collapseBlankRuns(s string) string {
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return s
}

// ---------------------------------------------------------------------------
// payload
// ---------------------------------------------------------------------------

// buildPayload renders the commit records, shrinking bodies (never dropping
// commits) until the whole thing fits the budget.
func buildPayload(commits []commit, bodyCap, maxInput int) (string, error) {
	cap := bodyCap
	for {
		payload := renderPayload(commits, cap)
		if len(payload) <= maxInput {
			if cap != bodyCap {
				logf(">> payload over budget: commit bodies truncated to %d bytes each (all %d commits retained)", cap, len(commits))
			}
			return payload, nil
		}
		if cap <= bodyCapFloor {
			return "", fmt.Errorf("payload is %d bytes at the %d-byte body floor, over -max-input=%d — narrow -from or raise -max-input",
				len(payload), bodyCapFloor, maxInput)
		}
		if cap /= 2; cap < bodyCapFloor {
			cap = bodyCapFloor
		}
	}
}

func renderPayload(commits []commit, bodyCap int) string {
	var b strings.Builder
	for i, c := range commits {
		fmt.Fprintf(&b, "<commit index=\"C%d\" date=%q>\n<subject>%s</subject>\n",
			i+1, c.Date, c.Subject)
		if body := truncateLines(c.Body, bodyCap); body != "" {
			fmt.Fprintf(&b, "<body>\n%s\n</body>\n", body)
		}
		b.WriteString("</commit>\n\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// truncateLines cuts at a line boundary so a truncated body never ends
// mid-sentence in a way that reads as a complete (but wrong) statement.
func truncateLines(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := strings.LastIndex(s[:limit], "\n")
	if cut <= 0 {
		cut = limit
	}
	return strings.TrimRight(s[:cut], "\n") + "\n[…truncated]"
}

// ---------------------------------------------------------------------------
// prompt
// ---------------------------------------------------------------------------

type profile struct {
	product     string
	description string
	audience    string
	releaseRepo string
}

var profiles = map[string]profile{
	"zs-proxy": {
		product: "zs-proxy",
		description: "the local, OpenAI-compatible proxy people run on their own machine to point " +
			"Claude Code, Cline, the OpenAI SDKs and similar tools at the ZeroSignal network, paying " +
			"per request from their own wallet.",
		audience: "Developers running zs-proxy on a laptop or a server. Most arrived via a package\n" +
			"manager, the setup wizard, or an editor integration; some are still evaluating whether to\n" +
			"route their daily coding tool through it. They care about their tools working, requests\n" +
			"not failing, and knowing what a request costs.",
		releaseRepo: "txnlab/zs-proxy",
	},
	"zs-node": {
		product: "zs-node",
		description: "the operator daemon that serves inference to the ZeroSignal network from an " +
			"operator's own GPUs or upstream API keys, and is paid on-chain per request.",
		audience: "Node operators running zs-node on their own hardware or a rented GPU box. They\n" +
			"hand-tune a YAML config, care about uptime, correct billing, and not losing money on\n" +
			"mispriced requests, and they read release notes specifically to decide whether an upgrade\n" +
			"needs a config change before they restart.",
		releaseRepo: "txnlab/zs-node",
	},
}

func profileFor(product string) (profile, error) {
	if p, ok := profiles[product]; ok {
		return p, nil
	}
	names := make([]string, 0, len(profiles))
	for k := range profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return profile{}, fmt.Errorf("unknown -product %q (known: %s)", product, strings.Join(names, ", "))
}

func (p profile) systemPrompt() string {
	return strings.NewReplacer(
		"{{PRODUCT}}", p.product,
		"{{PRODUCT_DESC}}", p.description,
		"{{AUDIENCE}}", p.audience,
		"{{RELEASE_REPO}}", p.releaseRepo,
	).Replace(systemPromptTemplate)
}

func (p profile) userPrompt(n int, payload string) string {
	return strings.NewReplacer(
		"{{PRODUCT}}", p.product,
		"{{N}}", strconv.Itoa(n),
		"{{PAYLOAD}}", payload,
	).Replace(userPromptTemplate)
}

const systemPromptTemplate = `You are the release-notes editor for {{PRODUCT}}, {{PRODUCT_DESC}}

You turn a set of git commits from a PRIVATE source repository into the PUBLIC release notes
published on the {{RELEASE_REPO}} GitHub release page and mirrored into a Discord announcement.
Your output is published essentially verbatim to people who did not write this code and cannot
see the source.

## Audience

{{AUDIENCE}}

They care about what they can now do that they couldn't, what stopped being broken, what they must
change when they upgrade, and what it costs them. They do not care how the code is organised.

## Hard rules

1. PUBLIC SAFETY. The source repository is private. Never emit, and never paraphrase closely
   enough to reveal: file paths, directory names, package names, type names, function names,
   struct fields, or any internal identifier; commit hashes, verbatim commit-message quotes,
   branch names, author names, or PR/issue numbers; internal module paths or the private
   repository's name; unreleased or in-progress work, internal roadmap, security findings not
   already fixed and shipped in THIS release, customer names, credentials, hostnames, wallet
   addresses, or private endpoints.
   Things a user already types or already sees are PUBLIC, and you SHOULD name them precisely:
   CLI commands and subcommands, config file keys, environment variables, HTTP endpoint paths,
   flag names, error codes returned to clients, and model ids. When in doubt, describe the
   behaviour instead of naming the thing that implements it.

2. NEVER INVENT. Every claim must be traceable to the commits you were given. No speculative
   benefits, no "this should improve performance" unless a commit says so, no invented numbers,
   benchmarks, percentages, dates, version numbers, or compatibility claims. If the commits don't
   say why something changed, say what changed and stop. Do not add "Known issues", "Coming next",
   "Thanks", or "Contributors" sections — you have no source for them.

3. NO VERSION HEADING. Do not emit a version number, tag name, release name, or date anywhere.
   The GitHub release title and the Discord message already carry the version. Do not open with
   "Release Notes" or "Changelog".

4. RAW MARKDOWN ONLY. Your entire response is the contents of the file. Do not wrap it in a code
   fence. No preamble, no sign-off, no note about what you did or how you decided. No HTML.
   The first character of your response is "#".

5. OMIT, DON'T PAD. A commit with no user-observable effect — internal refactor, tests, CI, code
   comments, internal-only docs — gets no bullet at all. But never omit a behaviour change, a fix,
   a new capability, a changed default, or anything that changes what a user must configure or
   run. Delete any section that would be empty, heading and all.

6. ONE BULLET PER CHANGE. Several commits that build one capability collapse into a single bullet
   describing the finished capability. A commit that fixes an earlier commit in this same list is
   folded into it and NOT listed as a fix — from the user's point of view that bug never shipped.

## Output format

Emit these sections, in this order, dropping any that would be empty.

### Breaking changes
Anything that can break a working setup on upgrade: removed or renamed config keys, environment
variables, CLI flags or endpoints, and defaults whose change alters behaviour. One bullet each,
shaped as: ` + "`**<what changed>** — <what breaks>, <what to do instead>.`" + `

### Highlights
The three to six changes that most change what a user can do. Feature-led. Start each bullet with
a short bold phrase naming the capability, then one sentence of plain consequence. Order by how
much a user would care, not by commit order.

### Improvements
Everything else user-visible that is neither a fix nor a highlight. One line each; no bold lead-in.

### Fixes
What was broken and now is not, written as the SYMPTOM a user would have seen — not the internal
cause. "Image requests were billed for the size you asked for rather than the size you got" beats
"corrected the reserve sizing path".

### Upgrade notes
Only if a user must actually DO something: run a command, edit config, re-run a wizard, restart
with a new flag. Numbered, imperative steps. If nothing is required, delete this section — do not
write "no action required".

### Details
Two to four short paragraphs of prose, no bullets. Explain what this release is ABOUT: the theme
connecting the changes, the problem it set out to solve, and what a user should expect to feel
differently. Nuance that didn't fit a bullet goes here — the tradeoff, why a default moved, how
far a fix reaches. Write it as a person answering "what's in this one?". No marketing language,
no superlatives, no "we're excited to announce".

## Budget

Everything ABOVE the ` + "`### Details`" + ` heading is mirrored into a Discord embed that is cut at 60
lines / 3800 bytes. Keep that part to at most 40 lines and 3000 characters, including headings and
blank lines, and at most 20 bullets in total. If there is more material than that, merge the
smaller items into broader bullets rather than dropping them.

## Voice

Second person, or subjectless. Present tense for what the software now does, past tense for what
was broken. No "we" or "our team", no emoji, no exclamation marks. Sentence case in bullets. Don't
restate the section name inside its own bullets ("Fixed a bug where…" under "Fixes" is redundant —
write the symptom). Never begin a bullet with a conventional-commit prefix such as ` + "`feat:`" + ` or
` + "`fix(node):`" + `; those are internal.`

const userPromptTemplate = `Write the public release notes for {{PRODUCT}}, covering the {{N}} commits below.

They are the complete set of non-merge commits between the previous release and this one, in
chronological order, oldest first. Later commits may correct or supersede earlier ones — read the
whole set before you write anything.

Each record carries an index, the commit date, the subject line, and the full commit message body.
The index is an internal handle for your own reasoning; it must not appear in your output.

The commit messages were written by maintainers, for maintainers. They name internal code and
internal reasoning. Your job is to translate them into what a user of {{PRODUCT}} experiences.

<changes>
{{PAYLOAD}}
</changes>

Now write the release notes. Output only the Markdown body, beginning with a ` + "`###`" + ` heading.`

// ---------------------------------------------------------------------------
// drafting call
// ---------------------------------------------------------------------------

type chatRequest struct {
	Model    string        `json:"model"`
	Stream   bool          `json:"stream"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// streamChunk is one frame of an OpenAI SSE stream.
//
// `choices` is legitimately empty on a usage-only chunk, and `error` appears in
// place of choices when a failure lands mid-stream — SPEC §5.3, where the proxy
// emits `data: {"error": …}` followed by a plaintext `[DONE]`. Both reasoning
// spellings are read because backends disagree: vLLM emits `reasoning_content`
// and the node normalizes to `reasoning`, so which one arrives depends on how
// far up the chain the normalization happened.
type streamChunk struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Delta        struct {
			Content          string `json:"content"`
			Reasoning        string `json:"reasoning"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"delta"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string          `json:"message"`
		Code    json.RawMessage `json:"code"`
	} `json:"error"`
}

// draftResult accumulates one drafting attempt.
//
// received is atomic because the progress ticker reads it while readSSE writes
// it. It is also the billing signal: the proxy opens the escrow ticket on the
// reserve leg, which has already succeeded by the time any frame arrives.
type draftResult struct {
	received atomic.Int64
	// keepRaw gates raw, whose only consumer is -debug-dir. Buffering an
	// unbounded stream twice by default replaced the old
	// io.LimitReader(1<<24) cap with no cap at all.
	keepRaw    bool
	raw        bytes.Buffer
	content    string
	reasoning  string
	finish     string
	prompt     int
	completion int
}

// apiError is the OpenAI-shaped envelope both the proxy and the node emit.
// `code` is a string in this system but a number elsewhere in OpenAI-land, so
// it is decoded leniently.
type apiError struct {
	Error struct {
		Message string          `json:"message"`
		Type    string          `json:"type"`
		Code    json.RawMessage `json:"code"`
	} `json:"error"`
}

func (e apiError) code() string {
	raw := strings.TrimSpace(string(e.Error.Code))
	if raw == "" || raw == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(e.Error.Code, &s); err == nil {
		return s
	}
	return strings.Trim(raw, `"`)
}

func draft(o *options, system, user string) (string, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := preflight(ctx, o); err != nil {
		return "", err
	}

	reqBody, err := json.Marshal(chatRequest{
		Model: o.model,
		// Streamed, and that is load-bearing rather than cosmetic. A buffered
		// call is byte-silent from admission until the whole answer is sealed,
		// and an intermediary in front of an operator or a transport-privacy
		// relay — a CDN, an ingress, an LB — resets a silent connection at its
		// idle timeout (60s is a common default) and answers with its own HTML
		// 5xx, which no amount of client-side -timeout can outlast. Streaming
		// keeps bytes moving: the node emits a ": zs-keepalive" comment through
		// a long prefill, and the deltas cover the rest.
		Stream: true,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		// Deliberately NO max_tokens / temperature / top_p / response_format.
		// Reasoning models reject the first two in this system, and the proxy
		// derives the per-operator max-output when they are omitted. Do not
		// "helpfully" add sampling params here.
	})
	if err != nil {
		return "", err
	}
	if err := dumpDebug(o.debugDir, "request.json", reqBody); err != nil {
		return "", err
	}

	// started spans the whole call, retry and backoff included — this is the
	// summary line's wall clock, deliberately not startProgress's per-attempt
	// elapsed.
	started := time.Now()
	res, err := postWithRetry(ctx, o, reqBody)
	if res != nil && o.debugDir != "" {
		// Dumped before the checks below, so a run that fails ON the draft
		// still leaves the partial draft behind to look at. A dump failure is
		// reported but must never mask the error that actually ended the run.
		for name, data := range map[string][]byte{
			"response.sse": res.raw.Bytes(),
			"response.txt": []byte(res.content),
		} {
			if derr := dumpDebug(o.debugDir, name, data); derr != nil {
				logf(">> warning: could not write %s: %v", name, derr)
			}
		}
	}
	if err != nil {
		return "", err
	}

	content, err := validateDraft(res)
	if err != nil {
		return "", err
	}
	// Usage is best-effort on a stream: the node forces stream_options.
	// include_usage for its own billing and strips the resulting usage-only
	// chunk back out, so the count that reaches us depends on the backend's
	// shape. Fall back to the byte count rather than printing a bare 0.
	if res.completion > 0 {
		logf(">> %s: %d prompt + %d completion tokens in %s",
			o.model, res.prompt, res.completion, time.Since(started).Round(time.Second))
	} else {
		logf(">> %s: %d chars in %s", o.model, len(content), time.Since(started).Round(time.Second))
	}
	return content, nil
}

// validateDraft is the last gate before a draft is written to a file that gets
// published verbatim. Split out from draft() so it is reachable in a test
// without standing up a proxy — these three refusals are the publish-safety
// rules, and an untested guard against publishing a truncated release note is
// not much of a guard.
func validateDraft(res *draftResult) (string, error) {
	// We can't cap output (see the request comment), so this is the only guard
	// against a body the model itself ran out of room to finish.
	if res.finish == "length" {
		return "", errors.New("model hit its output cap (finish_reason=length) — retry, or narrow the range")
	}
	content := strings.TrimSpace(res.content)
	if content == "" {
		if strings.TrimSpace(res.reasoning) != "" {
			return "", errors.New("model returned only reasoning content and no answer — retry, or try a different -model")
		}
		return "", errors.New("model returned empty content")
	}
	return content, nil
}

// preflight uses the free, unauthenticated discovery GETs to fail before any
// billed request: a request that reaches the chat endpoint opens an on-chain
// escrow ticket, so "is anything listening" and "is this model real" are much
// better answered up front.
func preflight(ctx context.Context, o *options) error {
	client := &http.Client{Timeout: 5 * time.Second}

	healthURL, err := healthzURL(o.baseURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("no proxy answering at %s — start one with 'zs-proxy proxy start', point -url at a running instance, or re-run with -offline", healthURL)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d — the proxy is not ready; re-run with -offline to skip the model", healthURL, resp.StatusCode)
	}

	models, err := listModels(ctx, client, o.baseURL)
	if err != nil {
		// Discovery is advisory: a reachable proxy with an unreadable model
		// list shouldn't block a drafting call that might well succeed.
		logf("WARNING: could not list models (%v) — continuing with %q", err, o.model)
		return nil
	}
	for _, id := range models {
		if id == o.model {
			return nil
		}
	}
	shown, more := models, ""
	if len(shown) > 20 {
		shown, more = shown[:20], fmt.Sprintf(" (and %d more)", len(models)-20)
	}
	return fmt.Errorf("model %q is not advertised by %s — available: %s%s\n"+
		"  pick one with -model / RELEASE_NOTES_MODEL", o.model, o.baseURL,
		strings.Join(shown, ", "), more)
}

func healthzURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("bad -url %q: %w", base, err)
	}
	u.Path, u.RawQuery, u.Fragment = "/healthz", "", ""
	return u.String(), nil
}

func listModels(ctx context.Context, client *http.Client, base string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<22)).Decode(&payload); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		ids = append(ids, m.ID)
	}
	if len(ids) == 0 {
		return nil, errors.New("proxy advertises no models")
	}
	return ids, nil
}

// postWithRetry makes at most two attempts, and only for a class that provably
// failed BEFORE the proxy opened an escrow ticket.
//
// This is the whole reason `post` computes retryability itself rather than
// letting the caller read a status: on a zs-proxy the reserve leg opens the
// escrow ticket and only then forwards, and the forward leg has no failover —
// so anything that reaches us from beyond the reserve (a 2xx that later fails
// mid-stream, or the gateway 502/504 the proxy passes back verbatim) has
// already been paid for. Re-sending those buys a second ticket, not a better
// answer. The result is returned even on a failure so the caller can still dump
// whatever arrived.
func postWithRetry(ctx context.Context, o *options, reqBody []byte) (*draftResult, error) {
	// -timeout bounds the whole drafting call, not each attempt. Per-attempt it
	// would silently be a 2x budget, and the ctx.Done() guard below could never
	// fire because the deadline would live on an inner context this select
	// cannot see. The deadline is on the context rather than on
	// http.Client.Timeout because a client timeout also bounds the body read,
	// which on a stream means cutting the response mid-frame — the same rule the
	// proxy and node SSE pumps follow.
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	res, retryable, err := post(ctx, o, reqBody)
	if err == nil || !retryable {
		return res, err
	}
	logf(">> %v — retrying once in %s", err, retryBackoff)
	select {
	case <-ctx.Done():
		return res, ctx.Err()
	case <-time.After(retryBackoff):
	}
	res, _, err = post(ctx, o, reqBody)
	return res, err
}

// retryBackoff is a var only so the tests don't have to sleep it.
var retryBackoff = 5 * time.Second

// dialFailed reports whether err is a failure to establish the connection at
// all — connection refused, DNS, an unreachable host.
//
// It exists because "the request failed before it was sent" is a claim about
// money, not about plumbing. http.Client.Do returns an error both when nothing
// was ever sent (free — no reserve happened) and when the body was delivered
// and the deadline expired waiting for headers (billed — the proxy's reserve
// leg is bounded by a 5s timeout, so a long silence past it is the forward leg,
// with the escrow ticket already open). Retrying the second buys a second
// ticket. Only a dial-stage failure is provably the first, so everything else
// is treated as spent: the asymmetry is a re-run against real money.
func dialFailed(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func post(ctx context.Context, o *options, reqBody []byte) (res *draftResult, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(o.baseURL, "/")+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "zs-release-notes/1")
	// The proxy discards Authorization; this only exists so -url can point at
	// some other OpenAI-compatible endpoint that needs it.
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	// The ticker starts before Do, not after the headers: dial → reserve →
	// first byte is the silent window a releaser most needs to see progress
	// through, and it is where a hung run hangs.
	res = &draftResult{keepRaw: o.debugDir != ""}
	stopProgress := startProgress(ctx, o.model, res)
	defer stopProgress()

	// Client.Timeout stays 0 — see postWithRetry. A slow trickle must outlive
	// any would-be client deadline; the context bounds the whole call.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, dialFailed(err), fmt.Errorf("POST /chat/completions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// A pre-stream rejection arrives whole: the proxy checks the operator's
		// Content-Type before committing any bytes, so even a gateway's HTML
		// error page is a complete body here rather than a half-written stream.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
		var envelope apiError
		json.Unmarshal(raw, &envelope)
		code, msg := envelope.code(), strings.TrimSpace(envelope.Error.Message)
		if msg == "" {
			msg = summarizeErrorBody(raw)
		}
		return nil, isRetryableStatus(resp.StatusCode, code),
			fmt.Errorf("%s: %s", statusHint(resp.StatusCode, code, o), msg)
	}

	// Diagnose a de-streamed 2xx by name. Without this an endpoint that ignored
	// `stream: true` (or a gateway that buffered the stream back into one body)
	// delivers a perfectly complete answer that readSSE then reports as "cut
	// short" — a misleading verdict that costs a ticket to reach.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		return res, false, fmt.Errorf(
			"POST /chat/completions: asked for a stream, got %q — the endpoint at %s ignored \"stream\": true",
			ct, o.baseURL)
	}

	if err := res.readSSE(resp.Body); err != nil {
		// A 2xx means the reserve leg already succeeded, so the ticket is open
		// whether or not a single frame arrived. Never retryable.
		return res, false, err
	}
	return res, false, nil
}

// startProgress ticks the elapsed time and the bytes received so far, so a
// stream that is alive but slow is visibly distinguishable from a hung one. It
// is per-attempt: the elapsed number must not carry across a retry, or "120s"
// silently means two 60s attempts.
func startProgress(ctx context.Context, model string, res *draftResult) (stop func()) {
	started := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				logf(">> waiting on %s … %ds (%s)", model,
					int(time.Since(started).Seconds()), humanBytes(res.received.Load()))
			}
		}
	}()
	return func() { close(done) }
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}

const sseDataPrefix = "data:"

// readSSE consumes an OpenAI SSE stream into res.
//
// bufio.Reader.ReadBytes('\n'), never bufio.Scanner: Scanner caps a line at
// 64KB and a single delta frame can exceed that. This is the same rule the
// proxy and node SSE pumps follow, for the same reason.
//
// The completion signal is `finish_reason`, and it is REQUIRED on every exit.
// `[DONE]` is a stream sentinel, not a statement that the model finished — a
// producer that emits one after a cut would otherwise hand back a draft that
// merely looks complete, which is this tool's worst failure because the result
// is published verbatim to a public release page. Same reasoning as the
// finish_reason=="length" guard: both refuse a partial answer rather than
// shipping one.
func (res *draftResult) readSSE(body io.Reader) error {
	var (
		br        = bufio.NewReaderSize(body, 64<<10)
		content   strings.Builder
		reasoning strings.Builder
	)
	// terminated is the shared exit: whatever ended the stream, an answer with
	// no finish_reason behind it was cut short.
	terminated := func(how string) error {
		res.content, res.reasoning = content.String(), reasoning.String()
		if res.finish == "" {
			return fmt.Errorf("stream %s after %s without a finish_reason — the response was cut short",
				how, humanBytes(res.received.Load()))
		}
		return nil
	}
	failed := func(format string, args ...any) error {
		res.content, res.reasoning = content.String(), reasoning.String()
		return fmt.Errorf(format, args...)
	}

	for {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			res.received.Add(int64(len(line)))
			if res.keepRaw {
				res.raw.Write(line)
			}

			// TrimRight over the line terminator only: an all-whitespace line
			// is an ignored field, not the blank line that ends a frame.
			trimmed := strings.TrimRight(string(line), "\r\n")
			switch {
			case trimmed == "":
				// Frame separator.
			case strings.HasPrefix(trimmed, ":"):
				// A comment — this is the node's ": zs-keepalive" through a
				// long prefill, the thing that keeps an intermediary from
				// resetting the connection. Carries no content.
			case strings.HasPrefix(trimmed, sseDataPrefix):
				data := strings.TrimSpace(trimmed[len(sseDataPrefix):])
				if data == "" {
					// An empty data field is a legal SSE keepalive, used by
					// some gateways in place of a comment. `break` leaves the
					// switch; `continue` here would skip the readErr handling
					// below and silently disable the terminator check.
					break
				}
				if data == "[DONE]" {
					// Always plaintext, even when the frames are sealed (§5.3).
					return terminated("ended")
				}
				var chunk streamChunk
				if err := json.Unmarshal([]byte(data), &chunk); err != nil {
					return failed("decode stream chunk: %w", err)
				}
				if chunk.Error != nil {
					msg := strings.TrimSpace(chunk.Error.Message)
					if msg == "" {
						msg = "(no message)"
					}
					if code := strings.Trim(strings.TrimSpace(string(chunk.Error.Code)), `"`); code != "" && code != "null" {
						msg = code + ": " + msg
					}
					return failed("stream failed after %s: %s", humanBytes(res.received.Load()), msg)
				}
				if chunk.Usage != nil {
					res.prompt, res.completion = chunk.Usage.PromptTokens, chunk.Usage.CompletionTokens
				}
				// An empty choices list is a usage-only chunk, not a defect.
				for _, c := range chunk.Choices {
					content.WriteString(c.Delta.Content)
					reasoning.WriteString(c.Delta.Reasoning)
					reasoning.WriteString(c.Delta.ReasoningContent)
					if c.FinishReason != "" {
						res.finish = c.FinishReason
					}
				}
			}
		}

		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return failed("read stream after %s: %w", humanBytes(res.received.Load()), readErr)
			}
			// A backend that closes on its terminal chunk instead of sending
			// [DONE] has still delivered a complete answer; terminated() is
			// what decides that, on the finish_reason and nothing else.
			return terminated("closed")
		}
	}
}

var htmlTitleRe = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// summarizeErrorBody keeps an un-enveloped error body readable. A code-less 5xx
// here is an operator's CDN or ingress, and those answer with a full HTML error
// page — dumping it raw buries the one line that matters under a screenful of
// markup. The retry usually rescues the run, so this text is often the only
// thing the releaser sees.
func summarizeErrorBody(raw []byte) string {
	body := strings.TrimSpace(string(raw))
	if body == "" {
		return "(empty body)"
	}
	if m := htmlTitleRe.FindStringSubmatch(body); m != nil {
		return "(HTML error page: " + strings.Join(strings.Fields(m[1]), " ") + ")"
	}
	body = strings.Join(strings.Fields(body), " ")
	if len(body) > 300 {
		body = body[:300] + "…"
	}
	return body
}

// isRetryableStatus answers "would asking again be both useful and free".
//
// The free half is the subtle one, and 502/504 are why it is spelled out. On a
// zs-proxy those are never the proxy's own: it opens the escrow ticket on the
// reserve leg and then forwards ONCE with no failover, so a 502/504 reaching us
// is an operator's CDN / ingress / LB answering from beyond a reserve that
// already succeeded — the work is admitted and billed. Re-sending buys a second
// ticket and, on a gateway that timed out because our own request was too slow
// for it, the identical failure. The proxy has already done the retrying that
// can help, rotating relays across the whole candidate list on the reserve leg.
func isRetryableStatus(status int, code string) bool {
	switch status {
	case http.StatusTooManyRequests:
		return true
	case http.StatusServiceUnavailable:
		// "nobody serves this model" never becomes true by asking again.
		return code != "no_operator" && code != "no_pinned_operator"
	}
	return false
}

func statusHint(status int, code string, o *options) string {
	switch {
	case status == http.StatusPaymentRequired:
		return "402 wallet_unfunded: the proxy wallet can't cover this request — fund it, or re-run with -offline"
	case status == http.StatusServiceUnavailable && (code == "no_operator" || code == "no_pinned_operator"):
		return fmt.Sprintf("503 %s: no operator is serving %q right now — pick another -model, or re-run with -offline", code, o.model)
	case status == http.StatusTooManyRequests:
		return "429: rate limited — retry shortly"
	}
	if code != "" {
		return fmt.Sprintf("POST /chat/completions: %d %s", status, code)
	}
	return fmt.Sprintf("POST /chat/completions: %d", status)
}

func dumpDebug(dir, name string, data []byte) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, 0o644)
}

// ---------------------------------------------------------------------------
// post-processing
// ---------------------------------------------------------------------------

var versionHeadingRe = regexp.MustCompile(`^#{1,2}\s+v?\d+\.\d+`)

// normalize repairs the two format slips worth repairing rather than re-billing
// a call for, then tidies whitespace.
func normalize(s string) string {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "```") {
		if end := strings.LastIndex(s, "```"); end > 0 {
			if nl := strings.Index(s, "\n"); nl > 0 && nl < end {
				logf("WARNING: model wrapped the notes in a code fence — stripped it")
				s = strings.TrimSpace(s[nl+1 : end])
			}
		}
	}

	lines := strings.Split(s, "\n")
	if len(lines) > 0 && versionHeadingRe.MatchString(lines[0]) {
		logf("WARNING: model emitted a version heading (%q) — stripped it (the release title carries the version)", lines[0])
		lines = lines[1:]
	}
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return collapseBlankRuns(strings.TrimSpace(strings.Join(lines, "\n"))) + "\n"
}

// publicFilenames are filenames a user legitimately sees and may need named.
var publicFilenames = map[string]bool{
	"config.yaml": true, "config.example.yaml": true, "config.yml": true,
	"readme.md": true, "license": true, "dockerfile": true,
	"release_notes.md": true, ".goreleaser.yaml": true, "makefile": true,
}

var (
	goFileRe   = regexp.MustCompile(`\b[\w./-]+\.go\b`)
	internalRe = regexp.MustCompile(`\binternal/\w+`)
	hashRe     = regexp.MustCompile(`\b[0-9a-f]{7,}\b`)
)

// looksLikeHash filters hashRe's hits down to plausible commit shas. Requiring a
// digit costs nothing against a real sha and drops the English words that happen
// to be spelled entirely in hex ("defaced", "effaced"). Maintainers do cite
// short shas in commit bodies, and those bodies ARE sent, so the output side has
// to catch a sha the model copied through — including one whose commit predates
// the range and therefore isn't in the locally-derived token set.
func looksLikeHash(s string) bool { return strings.ContainsAny(s, "0123456789") }

// scanForLeaks warns (never fails — this is a draft for human review) when the
// notes appear to name something from the private repo. Everything it scans for
// is derived LOCALLY, from data the model was never sent: paths, author names,
// and hashes are excluded from the payload by construction, so a hit here means
// the model reconstructed an internal name from a commit body.
func scanForLeaks(g *git, rng, notes string) {
	leaks := findLeaks(notes, collectForbidden(g, rng))
	for _, l := range leaks {
		logf("WARNING: possible private-repo leak, line %d: %q", l.line, l.token)
	}
	if len(leaks) > 0 {
		logf("WARNING: %d possible leak(s) above — the source repo is PRIVATE and this file is published publicly. Edit before 'make release'.", len(leaks))
	}
}

// collectForbidden derives the private-repo token set from git, locally.
func collectForbidden(g *git, rng string) map[string]bool {
	forbidden := map[string]bool{}
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if len(tok) >= 4 && !publicFilenames[strings.ToLower(tok)] {
			forbidden[strings.ToLower(tok)] = true
		}
	}

	// Full paths and extension-bearing basenames only. Bare directory segments
	// are deliberately NOT added: "server", "node", "proxy", "wallet", "models"
	// are all legitimate release-note vocabulary here, and flagging them would
	// make this scan cry wolf on every run until someone stopped reading it.
	// Bare internal directories are covered generically by internalRe instead.
	if out, err := g.run("log", "--name-only", "--pretty=format:", rng); err == nil {
		for _, path := range strings.Fields(out) {
			add(path)
			if base := filepath.Base(path); strings.Contains(base, ".") {
				add(base)
			}
		}
	}
	if out, err := g.run("log", "--pretty=format:%an%n%ae", rng); err == nil {
		for _, line := range strings.Split(out, "\n") {
			add(line)
			if local, _, ok := strings.Cut(line, "@"); ok {
				add(local)
			}
		}
	}
	if out, err := g.run("log", "--pretty=format:%H", rng); err == nil {
		for _, h := range strings.Fields(out) {
			for _, n := range []int{7, 8, 12, 40} {
				if len(h) >= n {
					add(h[:n])
				}
			}
		}
	}
	// The private repo's own name ("hayai-proxy" / "hayai-node"); the public
	// binary names ("zs-proxy" / "zs-node") are legitimate and stay unflagged.
	if out, err := g.run("config", "--get", "remote.origin.url"); err == nil {
		remote := strings.TrimSpace(out)
		add(remote)
		add(strings.TrimSuffix(filepath.Base(remote), ".git"))
	}
	return forbidden
}

type leak struct {
	line  int
	token string
}

func findLeaks(notes string, forbidden map[string]bool) []leak {
	var leaks []leak
	for i, line := range strings.Split(notes, "\n") {
		lower := strings.ToLower(line)
		reported := map[string]bool{}
		report := func(tok string) {
			if tok == "" || reported[tok] {
				return
			}
			reported[tok] = true
			leaks = append(leaks, leak{line: i + 1, token: tok})
		}
		for tok := range forbidden {
			if strings.Contains(lower, tok) {
				report(tok)
			}
		}
		for _, m := range goFileRe.FindAllString(line, -1) {
			report(m)
		}
		for _, m := range internalRe.FindAllString(line, -1) {
			report(m)
		}
		for _, m := range hashRe.FindAllString(lower, -1) {
			if looksLikeHash(m) {
				report(m)
			}
		}
	}
	// Map iteration is random; a stable order keeps the warnings readable.
	sort.SliceStable(leaks, func(a, b int) bool {
		if leaks[a].line != leaks[b].line {
			return leaks[a].line < leaks[b].line
		}
		return leaks[a].token < leaks[b].token
	})
	return leaks
}

// checkDiscordBudget measures the part `make release` slices into the Discord
// embed (everything above the Details narrative).
func checkDiscordBudget(notes string) {
	summary := notes
	if i := strings.Index(notes, "\n### Details"); i >= 0 {
		summary = notes[:i]
	}
	lines := strings.Count(summary, "\n") + 1
	if lines > discordLines || len(summary) > discordBytes {
		logf("WARNING: the summary above '### Details' is %d lines / %d bytes — the Discord embed cuts at 60 lines / 3800 bytes, so it will be truncated mid-section. Trim it.",
			lines, len(summary))
	}
}

// ---------------------------------------------------------------------------
// offline (deterministic) output
// ---------------------------------------------------------------------------

// offlineNotes reproduces the awk one-liner this tool replaced, byte for byte:
// commit subjects bucketed on their conventional-commit prefix, newest first,
// empty sections omitted. Keeping it byte-identical makes the regression check
// a plain `diff` against the old target.
//
// It re-reads the range rather than reusing the parsed commits, because the old
// target emitted subjects newest-first while the drafting payload is
// oldest-first, and byte-identity is the whole point of this path.
func offlineNotes(g *git, rng string) (string, error) {
	subjects, err := g.subjectsNewestFirst(rng)
	if err != nil {
		return "", err
	}
	return offlineFromSubjects(subjects), nil
}

func offlineFromSubjects(subjects []string) string {
	var feat, fix, perf, other []string
	for _, s := range subjects {
		switch {
		case hasConventionalPrefix(s, "feat"):
			feat = append(feat, s)
		case hasConventionalPrefix(s, "fix"):
			fix = append(fix, s)
		case hasConventionalPrefix(s, "perf"):
			perf = append(perf, s)
		default:
			other = append(other, s)
		}
	}
	var b strings.Builder
	flush := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "### %s\n\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "- %s\n", it)
		}
		b.WriteString("\n")
	}
	flush("Features", feat)
	flush("Bug Fixes", fix)
	flush("Performance", perf)
	flush("Other Changes", other)
	return b.String()
}

// hasConventionalPrefix matches awk's /^feat(\(|!|:)/ — the type followed by a
// scope, a breaking-change bang, or the colon.
func hasConventionalPrefix(subject, typ string) bool {
	if !strings.HasPrefix(subject, typ) {
		return false
	}
	rest := subject[len(typ):]
	return strings.HasPrefix(rest, "(") || strings.HasPrefix(rest, "!") || strings.HasPrefix(rest, ":")
}
