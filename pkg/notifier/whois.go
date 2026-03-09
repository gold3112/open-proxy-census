package notifier

import (
	"log"
	"strings"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// GetAbuseEmail fetches WHOIS info for an IP and tries to extract an abuse email address
func GetAbuseEmail(ip string) (string, error) {
	raw, err := whois.Whois(ip)
	if err != nil {
		return "", err
	}

	result, err := whoisparser.Parse(raw)
	if err != nil {
		// If parser fails, we can still try manual extraction from raw
		return manualExtract(raw), nil
	}

	var email string
	if result.Administrative != nil && result.Administrative.Email != "" {
		email = result.Administrative.Email
	} else if result.Technical != nil && result.Technical.Email != "" {
		email = result.Technical.Email
	} else if result.Registrant != nil && result.Registrant.Email != "" {
		email = result.Registrant.Email
	}

	if email == "" {
		email = manualExtract(raw)
	}

	if email != "" {
		log.Printf("WHOIS for %s: found email %s", ip, email)
	}
	return strings.ToLower(email), nil
}

func manualExtract(raw string) string {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "abuse-mailbox") || strings.Contains(lower, "abuse@") || strings.Contains(lower, "abuse-email") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, "@") {
					// Clean common prefixes like "email:" or "mailbox:"
					clean := strings.Trim(p, ": ")
					idx := strings.Index(clean, "@")
					if idx > 0 {
						return clean
					}
				}
			}
		}
	}
	return ""
}
