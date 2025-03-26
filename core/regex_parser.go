package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// RegexPatternMap is a map of predefined regex patterns
var RegexPatternMap = map[string]string{
	"google_api":               `AIza[0-9A-Za-z-_]{35}`,
	"firebase":                 `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"firebase_url":             `.*firebaseio\.com`,
	"google_captcha":           `6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`,
	"google_oauth":             `ya29\.[0-9A-Za-z\-_]+`,
	"amazon_aws_access_key_id": `A[SK]IA[0-9A-Z]{16}`,
	"amazon_mws_auth_toke":     `amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"amazon_aws_url":           `s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`,
	"amazon_aws_url2":          `([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)`,
	"facebook_access_token":    `EAACEdEose0cBA[0-9A-Za-z]+`,
	"facebook_oauth":           `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`,
	"authorization_basic":      `basic [a-zA-Z0-9=:_\+\/-]{5,100}`,
	"authorization_bearer":     `bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`,
	"authorization_api":        `api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`,
	"mailgun_api_key":          `key-[0-9a-zA-Z]{32}`,
	"mailchimp_api_key":        `[0-9a-f]{32}-us[0-9]{1,2}`,
	"twilio_api_key":           `SK[0-9a-fA-F]{32}`,
	"twilio_account_sid":       `AC[a-zA-Z0-9_\-]{32}`,
	"twilio_app_sid":           `AP[a-zA-Z0-9_\-]{32}`,
	"paypal_braintree_access_token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"square_oauth_secret":      `sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`,
	"square_access_token":      `sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}|sq0atp-[0-9A-Za-z\-_]{22}`,
	"stripe_standard_api":      `sk_live_[0-9a-zA-Z]{24}`,
	"stripe_restricted_api":    `rk_live_[0-9a-zA-Z]{24}`,
	"github_access_token":      `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`,
	"github":                   `[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]`,
	"rsa_private_key":          `-----BEGIN RSA PRIVATE KEY-----`,
	"ssh_dsa_private_key":      `-----BEGIN DSA PRIVATE KEY-----`,
	"ssh_ec_private_key":       `-----BEGIN EC PRIVATE KEY-----`,
	"pgp_private_block":        `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"json_web_token":           `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`,
	"slack_token":              `\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"|xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
	"slack_webhook":            `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
	"SSH_privKey":              `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
	"Heroku API KEY":           `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	"possible_Creds":           `(?i)(password\s*[`+"`"+`=:\"]+\s*[^\s]+|password is\s*[`+"`"+`=:\"]*\s*[^\s]+|pwd\s*[`+"`"+`=:\"]*\s*[^\s]+|passwd\s*[`+"`"+`=:\"]+\s*[^\s]+)`,
	"cloudinary":               `cloudinary://.*`,
	"aws_api_key":              `AKIA[0-9A-Z]{16}`,
	"password_in_url":          `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\\s]`,
	"picatic_api_key":          `sk_live_[0-9a-z]{32}`,
	"generic_api_key":          `[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]`,
	"generic_secret":           `[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]`,
	"google_cloud_platform_api_key": `AIza[0-9A-Za-z\-_]{35}`,
	"google_cloud_platform_oauth": `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"google_drive_api_key":     `AIza[0-9A-Za-z\-_]{35}`,
	"google_drive_oauth":       `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"google_gcp_service_account": `"type": "service_account"`,
	"google_gmail_api_key":     `AIza[0-9A-Za-z\-_]{35}`,
	"google_gmail_oauth":       `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"google_youtube_api_key":   `AIza[0-9A-Za-z\-_]{35}`,
	"google_youtube_oauth":     `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"twitter_access_token":     `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	"twitter_oauth":            `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]`,
}

// LoadPredefinedPatterns loads the predefined regex patterns into the RegexManager
func (rm *RegexManager) LoadPredefinedPatterns() error {
	for name, pattern := range RegexPatternMap {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile predefined regex '%s': %v", name, err)
		}
		rm.patterns[name] = re
	}
	return nil
}

// ParseRegexFile parses a regex file with a specific format
func ParseRegexFile(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open regex file: %v", err)
	}
	defer file.Close()

	patterns := make(map[string]string)
	scanner := bufio.NewScanner(file)
	var inPatternSection bool
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for the start of the pattern section
		if strings.HasPrefix(line, "REGEX_PATTERNS = {") {
			inPatternSection = true
			continue
		}

		// Check for the end of the pattern section
		if line == "}" {
			break
		}

		// Process pattern lines
		if inPatternSection {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			// Extract pattern name and regex
			patternName := strings.Trim(parts[0], " '\",")
			patternRegex := strings.Trim(parts[1], " '\",")
			
			// Remove trailing comma if present
			patternRegex = strings.TrimSuffix(patternRegex, ",")
			
			patterns[patternName] = patternRegex
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading regex file: %v", err)
	}

	if len(patterns) == 0 {
		return nil, fmt.Errorf("no regex patterns found in file")
	}

	return patterns, nil
}
