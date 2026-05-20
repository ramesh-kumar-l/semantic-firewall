package normalize

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

const detectorName = "normalizer_v1"

// Result holds the normalized prompt and any encoding-trick findings discovered.
type Result struct {
	Normalized string
	Findings   []types.Finding
}

var (
	zwsRe    = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{00AD}\x{2060}]`)
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	urlEncRe = regexp.MustCompile(`(?i)%[0-9A-Fa-f]{2}`)
)

// rot13Canaries maps ROT13 forms of known attack keywords to their plaintext.
var rot13Canaries = map[string]string{
	"vtaber":      "ignore",
	"flfgrz":      "system",
	"wnvyoernx":   "jailbreak",
	"cebzcg":      "prompt",
	"vafgehpgvba": "instruction",
}

// Normalize strips encoding tricks from prompt and returns a cleaned copy plus findings.
func Normalize(prompt string) Result {
	var findings []types.Finding
	normalized := prompt

	// 1. Strip zero-width / invisible Unicode chars.
	if zwsRe.MatchString(normalized) {
		findings = append(findings, types.Finding{
			Type:     types.FindingEncodingTrick,
			Severity: types.SeverityHigh,
			Evidence: "zero-width or invisible Unicode characters detected",
			Detector: detectorName,
		})
		normalized = zwsRe.ReplaceAllString(normalized, "")
	}

	// 2. NFKC: collapses homoglyphs and Unicode compatibility characters.
	if nfkc := norm.NFKC.String(normalized); nfkc != normalized {
		findings = append(findings, types.Finding{
			Type:     types.FindingEncodingTrick,
			Severity: types.SeverityMedium,
			Evidence: "Unicode homoglyph or compatibility characters normalized (NFKC)",
			Detector: detectorName,
		})
		normalized = nfkc
	}

	// 3. URL percent-encoding.
	if urlEncRe.MatchString(normalized) {
		decoded, err := url.QueryUnescape(strings.ReplaceAll(normalized, "+", "%2B"))
		if err == nil && decoded != normalized {
			findings = append(findings, types.Finding{
				Type:     types.FindingEncodingTrick,
				Severity: types.SeverityHigh,
				Evidence: "URL percent-encoded characters decoded",
				Detector: detectorName,
			})
			normalized = decoded
		}
	}

	// 4. Base64 segment detection — replace decodable ASCII segments with plaintext.
	if b64Findings, b64Norm := decodeBase64Segments(normalized); len(b64Findings) > 0 {
		findings = append(findings, b64Findings...)
		normalized = b64Norm
	}

	// 5. ROT13 canary detection.
	lower := strings.ToLower(normalized)
	for canary, plain := range rot13Canaries {
		if strings.Contains(lower, canary) {
			findings = append(findings, types.Finding{
				Type:     types.FindingEncodingTrick,
				Severity: types.SeverityHigh,
				Evidence: fmt.Sprintf("ROT13-encoded keyword detected: %q → %q", canary, plain),
				Detector: detectorName,
			})
			normalized = rot13(normalized)
			break // apply ROT13 once; remaining canaries checked on decoded text
		}
	}

	return Result{Normalized: normalized, Findings: findings}
}

func decodeBase64Segments(prompt string) ([]types.Finding, string) {
	var findings []types.Finding
	result := base64Re.ReplaceAllStringFunc(prompt, func(match string) string {
		b, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			b, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				return match
			}
		}
		decoded := string(b)
		if isPrintableASCII(decoded) && utf8.RuneCountInString(decoded) >= 8 {
			findings = append(findings, types.Finding{
				Type:     types.FindingEncodingTrick,
				Severity: types.SeverityHigh,
				Evidence: fmt.Sprintf("base64 segment decoded: %q", truncate(decoded, 80)),
				Detector: detectorName,
			})
			return decoded
		}
		return match
	})
	return findings, result
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
		if b == 127 {
			return false
		}
	}
	return true
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
