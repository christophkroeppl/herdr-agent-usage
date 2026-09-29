/**
 * Usage extraction from Kilo's session rows. Pure parsing only: no file or
 * database access happens here.
 *
 * Kilo records two things that matter for display, in two different places:
 *
 *   part rows of type "step-finish"  one completed model step, carrying that
 *                                    step's exact context size and its provider
 *                                    and model ids. This is the same row Kilo's
 *                                    own "Token Usage" sidebar reads, and the
 *                                    same row the partial index
 *                                    part_session_step_finish_idx exists for.
 *
 *   message rows                    one assistant turn. Newer rows repeat the
 *                                    provider and model at the top level; older
 *                                    rows only have modelID, and rows written
 *                                    by a v2 client nest them under "model".
 *
 * The newest step-finish row is the authoritative context reading, so the
 * model/provider identity comes from the message that owns the step and falls
 * back to the step itself, which is what Kilo's own query does.
 */
package kilo

import (
	"encoding/json"
	"strconv"
	"strings"
)

// maxPartBytes caps how much of a single part payload is parsed. A step-finish
// row is a few hundred bytes; anything an order of magnitude larger is not the
// row we are looking for and is skipped rather than allocated for.
const maxPartBytes = 1 << 20

// StepUsage is one completed model step, decoded from a part row.
type StepUsage struct {
	// ContextTokens is the prompt-cache-occupying count for this step:
	// input plus cache read plus cache write. Output and reasoning tokens are
	// already folded into the next step's input, so counting them here would
	// double-count a context window. This matches the OpenCode provider's rule.
	ContextTokens int
	CacheFresh    int
	CacheRead     int
	CacheWrite    int
	ProviderID    string
	ModelID       string
}

// MessageIdentity is the provider/model a message was served by.
type MessageIdentity struct {
	ProviderID string
	ModelID    string
}

// ParseStepUsage decodes one part row. It returns nil for anything that is not
// a completed step, or whose payload is too large or malformed to trust.
func ParseStepUsage(raw string) *StepUsage {
	if raw == "" || len(raw) > maxPartBytes {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil
	}
	if asString(data["type"]) != "step-finish" {
		return nil
	}
	tokens, _ := data["tokens"].(map[string]any)
	if tokens == nil {
		// A step-finish with no token block carries no context reading. It is
		// still evidence of a completed step, but with nothing to report.
		return nil
	}
	cache, _ := tokens["cache"].(map[string]any)
	in := jsonInt(tokens["input"])
	read := jsonInt(mapValue(cache, "read"))
	write := jsonInt(mapValue(cache, "write"))
	out := jsonInt(tokens["output"])
	if in == 0 && read == 0 && write == 0 && out == 0 {
		// Kilo records cost-only steps (free models) with every counter at
		// zero. Reporting a 0-token context would present as an untouched
		// window, so this yields no usage at all.
		return nil
	}
	identity := MessageIdentity{}
	if model, ok := data["model"].(map[string]any); ok {
		identity.ProviderID = asString(model["providerID"])
		identity.ModelID = asString(model["modelID"])
		if identity.ModelID == "" {
			identity.ModelID = asString(model["id"])
		}
	}
	return &StepUsage{
		ContextTokens: in + read + write,
		CacheFresh:    in,
		CacheRead:     read,
		CacheWrite:    write,
		ProviderID:    identity.ProviderID,
		ModelID:       identity.ModelID,
	}
}

// ParseMessageIdentity decodes the provider and model a message was served by.
//
// A message written by a v2 client nests them under "model"; older rows carry
// modelID at the top level. Both spellings are accepted, and a row that names
// neither is skipped rather than attributed to a guessed provider.
func ParseMessageIdentity(raw string) MessageIdentity {
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return MessageIdentity{}
	}
	if model, ok := data["model"].(map[string]any); ok {
		identity := MessageIdentity{
			ProviderID: asString(model["providerID"]),
			ModelID:    asString(model["modelID"]),
		}
		if identity.ModelID == "" {
			identity.ModelID = asString(model["id"])
		}
		if identity.ProviderID != "" {
			return identity
		}
	}
	return MessageIdentity{
		ProviderID: asString(data["providerID"]),
		ModelID:    asString(data["modelID"]),
	}
}

// SessionSummary aggregates one session's denormalised usage columns.
//
// Kilo maintains cost and token totals directly on the session row and
// backfills them from the assistant messages, so they are cheaper and steadier
// than re-aggregating every part. They are lifetime totals for the session,
// not a window, so callers use them for pane activity and never for a context
// percentage.
type SessionSummary struct {
	Cost         float64
	TokensInput  int
	TokensOutput int
	TokensReason int
	TokensRead   int
	TokensWrite  int
	ProviderID   string
	ModelID      string
}

// TotalTokens is every token the session has moved through any path.
func (s SessionSummary) TotalTokens() int {
	return s.TokensInput + s.TokensOutput + s.TokensReason + s.TokensRead + s.TokensWrite
}

// SessionSummaryFromRow builds a summary from one scanned session row.
func SessionSummaryFromRow(cost float64, tokensInput, tokensOutput, tokensReasoning, tokensRead, tokensWrite int, modelJSON string) SessionSummary {
	summary := SessionSummary{
		Cost:         cost,
		TokensInput:  tokensInput,
		TokensOutput: tokensOutput,
		TokensReason: tokensReasoning,
		TokensRead:   tokensRead,
		TokensWrite:  tokensWrite,
	}
	// session.model is a JSON object {"id","providerID","variant"} and is only
	// populated on newer sessions, so an empty value here is normal and simply
	// leaves the pane without a backend name.
	if strings.TrimSpace(modelJSON) != "" {
		var model map[string]any
		if err := json.Unmarshal([]byte(modelJSON), &model); err == nil {
			summary.ModelID = asString(model["id"])
			summary.ProviderID = asString(model["providerID"])
		}
	}
	return summary
}

func mapValue(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func asString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// jsonInt reads a JSON number as an int without accepting floats, strings or
// negatives. Kilo writes these counters as plain integers; anything else is
// treated as absent rather than coerced.
func jsonInt(v any) int {
	switch value := v.(type) {
	case float64:
		if value <= 0 || value != float64(int64(value)) {
			return 0
		}
		return int(value)
	case json.Number:
		n, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil || n < 0 {
			return 0
		}
		return int(n)
	default:
		return 0
	}
}
