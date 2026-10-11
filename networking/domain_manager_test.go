package networking

import "testing"

func TestGroupURLsByDomainResetsDomainStats(t *testing.T) {
	manager := NewDomainManager()
	urls := []string{
		"https://example.com/a.js",
		"https://example.com/b.js",
	}

	manager.GroupURLsByDomain(urls)
	manager.GroupURLsByDomain(urls)

	stats := manager.GetDomainStatus()["example.com"]
	if stats.TotalURLs != len(urls) {
		t.Fatalf("TotalURLs = %d, want %d", stats.TotalURLs, len(urls))
	}
}
