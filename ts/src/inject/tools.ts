/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of the tool-classification surface in proto/go/inject that
// reserve sizing depends on: normalizeToolName, the not-billed table,
// classifyToolEntry and bodyDrivesServerSideToolGrowth.
//
// Only the reserve-sizing predicate is mirrored, not the pricing engine — but it
// transitively needs the same canonical-name folding and the same not-billed
// table, so those come with it. proto/testdata/tool_growth_vectors.json pins the
// two implementations together.
//
// Why the client needs this at all: sizing tool-loop headroom off "does the body
// carry any tools" over-reserves every request that offers a caller-executed
// function tool by max_tool_iterations x tool_headroom_per_iteration — 80,000
// tokens at the node's defaults — for a server-side loop that structurally
// cannot run. The proxy has always used the narrow predicate; the client used
// the broad one, so the two sides sized the same request differently.

/**
 * Whether a tool type names one of the node's own built-ins. Lives here rather
 * than in a one-function module mirroring Go's `tools` package — the growth
 * predicate is its only TS consumer.
 */
export function isBuiltinToolType(t: string): boolean {
  return t.startsWith('zs_')
}

/** Billing class of one tools[] entry. Mirrors Go's ToolClass. */
export type ToolClass = 'client' | 'not_billed' | 'vendor_billable'

type Billing = 'client_executed' | 'vendor_free'

/**
 * Canonical tool names that carry no vendor per-call fee by default. Mirrors
 * Go's notBilledTools — names are POST-normalizeToolName, so a request spelling
 * ({"type":"mcp"}) and a response spelling ("mcp_call") land on the same key.
 */
const NOT_BILLED_TOOLS: Record<string, Billing> = {
  // Caller-executed.
  function: 'client_executed',
  tool: 'client_executed',
  custom: 'client_executed', // OpenAI freeform tool ("custom_tool_call")
  local_shell: 'client_executed', // OpenAI local shell — the harness runs it
  apply_patch: 'client_executed', // OpenAI apply_patch — the harness applies it
  // computer_use: the model emits click/type/scroll actions and the CALLER's
  // harness performs them, so a computer_call item is the caller's work.
  computer_use: 'client_executed',
  // Anthropic's caller-executed tools, same category as local_shell. The
  // _YYYYMMDD version suffix is normalized away (bash_20250124 -> bash).
  bash: 'client_executed',
  text_editor: 'client_executed',
  str_replace_editor: 'client_executed',
  str_replace_based_edit_tool: 'client_executed',

  // Vendor-hosted but free: the upstream really executes it and may report a
  // count, it just charges no per-call fee. OpenAI's hosted "shell" tool
  // (vendor-managed containers) is deliberately NOT here — it bills per
  // container session, and only its environment.type "local" mode is exempt.
  mcp: 'vendor_free', // remote MCP connector (OpenAI, Anthropic, xAI)
}

/** Whether a canonical tool name carries no vendor per-call fee by default. */
export function isNotBilledToolName(canonical: string): boolean {
  return canonical in NOT_BILLED_TOOLS
}

/**
 * Whether a canonical tool name is executed by the CALLER, so a matching *_call
 * item is the caller's own work rather than a vendor server-side call. Narrower
 * than isNotBilledToolName: mcp is hosted-but-free, so the upstream really runs
 * it.
 */
export function isClientExecutedToolName(canonical: string): boolean {
  return NOT_BILLED_TOOLS[canonical] === 'client_executed'
}

function isAllDigits(s: string): boolean {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

/**
 * Reduces a vendor's tool identifier to a canonical key so one rate covers the
 * same logical tool across vendors and spellings. Strips a Moonshot "$" prefix,
 * an OpenAI "_call" / xAI "_calls" suffix and an Anthropic "_YYYYMMDD" version
 * suffix, then folds known aliases.
 */
export function normalizeToolName(raw: string): string {
  let n = raw.trim().toLowerCase()
  if (n.startsWith('$')) n = n.slice(1)
  // Trailing usage-field / output-item suffix.
  if (n.endsWith('_calls')) n = n.slice(0, -'_calls'.length)
  else if (n.endsWith('_call')) n = n.slice(0, -'_call'.length)
  // Anthropic dated tool version: web_search_20250305 -> web_search.
  const i = n.lastIndexOf('_')
  if (i > 0) {
    const suffix = n.slice(i + 1)
    if (suffix.length === 8 && isAllDigits(suffix)) n = n.slice(0, i)
  }
  switch (n) {
    case 'web_search_preview':
      return 'web_search'
    case 'computer':
    case 'computer_use_preview':
    case 'computer_use':
      return 'computer_use'
    case 'custom_tool':
      return 'custom'
    case 'code_execution':
      // xAI's primary name for what OpenAI calls code_interpreter.
      return 'code_interpreter'
    case 'collections_search':
      // xAI's file_search alias. Its pricier sibling attachment_search is a
      // DIFFERENT tool — don't fold.
      return 'file_search'
    default:
      return n
  }
}

function funcName(entry: Record<string, unknown>): string {
  const fn = entry.function
  if (fn !== null && typeof fn === 'object' && !Array.isArray(fn)) {
    const name = (fn as Record<string, unknown>).name
    if (typeof name === 'string') return name
  }
  return ''
}

/** Reads a shell tool entry's environment.type discriminator. */
function shellEnvironment(entry: Record<string, unknown>): string {
  const env = entry.environment
  if (env !== null && typeof env === 'object' && !Array.isArray(env)) {
    const t = (env as Record<string, unknown>).type
    if (typeof t === 'string') return t.trim().toLowerCase()
  }
  return ''
}

/**
 * Inspects one tools[] entry and reports its canonical name and billing class.
 * Mirrors Go's ClassifyToolEntry, including the default-deny fallback: an
 * unrecognised hosted type is vendor_billable.
 */
export function classifyToolEntry(entry: unknown): { name: string; class: ToolClass } {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    return { name: '', class: 'client' }
  }
  const obj = entry as Record<string, unknown>
  const rawType = typeof obj.type === 'string' ? obj.type : ''
  const typ = rawType.trim().toLowerCase()

  // Node's own built-ins and client function tools are never vendor tools.
  if (isBuiltinToolType(typ)) return { name: typ, class: 'client' }

  const fn = funcName(obj)

  switch (typ) {
    case 'function':
      return { name: fn, class: 'client' }
    case 'builtin_function':
      // Moonshot: the identifying name is the function name ($web_search).
      return { name: normalizeToolName(fn), class: 'vendor_billable' }
    case '':
      // No type: a bare {"function":{...}} or a "$"-named builtin.
      if (fn.startsWith('$')) return { name: normalizeToolName(fn), class: 'vendor_billable' }
      return { name: fn, class: 'client' }
    case 'shell': {
      // OpenAI's shell tool bills in its hosted modes, but environment.type
      // "local" runs on the CALLER's machine and is the documented successor to
      // the deprecated local_shell. Fold both onto one canonical key.
      if (shellEnvironment(obj) === 'local') return { name: 'local_shell', class: 'not_billed' }
      return { name: 'shell', class: 'vendor_billable' }
    }
    default: {
      // Any other type string is a hosted/server-side tool: billable by default
      // unless it is one of the known-free types.
      const n = normalizeToolName(typ)
      if (isNotBilledToolName(n)) return { name: n, class: 'not_billed' }
      return { name: n, class: 'vendor_billable' }
    }
  }
}

/**
 * Whether a request body carries a tool that will grow the SERVING side's
 * context within the reserve's lifetime — the signal a caller uses to add
 * tool-loop headroom to input_count.
 *
 * Deliberately narrower than bodyHasTools ("are there any tools at all"), which
 * over-reserves the common agent case. Two kinds of tool grow the context the
 * reserve has to cover, and one kind does not:
 *
 *   - A node zs_ built-in: the NODE runs the chat->tool->chat loop in-process,
 *     so the conversation grows across iterations inside one reserve.
 *   - A vendor-hosted tool (web_search, code_interpreter, mcp, ...): the
 *     UPSTREAM executes it inside a single completion and re-prefills each
 *     result into the context, so the input grows without the node ever seeing a
 *     new request. Free-of-charge hosted tools inflate context exactly like
 *     billed ones — the per-call fee is a separate axis.
 *   - A caller-executed tool ({"type":"function"} and the hosted-shaped types
 *     the harness actually runs: local_shell, apply_patch, computer_use,
 *     Anthropic's bash / text_editor) grows NOTHING here. The caller runs the
 *     tool and re-issues a fresh request, which is measured — and paid for — on
 *     its own.
 *
 * A malformed body reports false; the node's inference-time input-budget check
 * backstops any surprise growth.
 */
export function bodyDrivesServerSideToolGrowth(body: Uint8Array | string): boolean {
  let parsed: unknown
  try {
    const text = typeof body === 'string' ? body : new TextDecoder('utf-8').decode(body)
    if (text === '') return false
    parsed = JSON.parse(text)
  } catch {
    return false
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false
  const tools = (parsed as Record<string, unknown>).tools
  if (!Array.isArray(tools)) return false

  for (const entry of tools) {
    const { name, class: cls } = classifyToolEntry(entry)
    // A zs_ built-in classifies as 'client' (it is never vendor-billed), so the
    // loop signal has to come from the name, not the class.
    if (isBuiltinToolType(name)) return true
    if (cls !== 'client' && !isClientExecutedToolName(name)) return true
  }
  return false
}
