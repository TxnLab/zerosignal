/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package gcplog adapts stdlib slog output to the field names Google Cloud
// Logging recognizes in a structured (jsonPayload) log entry. Wire it into a
// JSON handler via slog.HandlerOptions.ReplaceAttr; it is a no-op shape for
// text handlers, which stay human-readable for local development.
package gcplog

import "log/slog"

// ReplaceAttr renames slog's builtin attribute keys to the names Cloud Logging
// special-cases, and rewrites the level value to a Cloud Logging severity
// string:
//
//	level -> severity   (value mapped to DEBUG/INFO/WARNING/ERROR)
//	msg   -> message
//
// The default time attr ("time", RFC3339Nano) is already accepted by Cloud
// Logging, so it is left untouched. Only top-level builtin keys are rewritten;
// grouped attrs (and any user attr nested under a group) pass through unchanged.
//
// Intended for slog.HandlerOptions.ReplaceAttr on a *slog.JSONHandler.
func ReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	// Builtin time/level/msg attrs are always emitted at the top level, so a
	// non-empty group means this is a nested attr we must not touch.
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.LevelKey:
		lvl, ok := a.Value.Any().(slog.Level)
		if !ok {
			return a
		}
		a.Key = "severity"
		a.Value = slog.StringValue(Severity(lvl))
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

// Severity maps an slog.Level to the closest Cloud Logging LogSeverity string.
// Threshold comparisons (rather than exact matches) keep custom intermediate
// levels sensible. Note slog's WARN becomes Cloud Logging's WARNING.
//
// https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
func Severity(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO"
	case l < slog.LevelError:
		return "WARNING"
	default:
		return "ERROR"
	}
}
