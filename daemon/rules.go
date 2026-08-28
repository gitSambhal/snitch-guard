// SnitchGuard - Host-Based Application Firewall Daemon
// Author: Suhail Akhtar (https://suhail.top)
// License: MIT
// Module: Rule Engine & JSON Persistence

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Action represents firewall verdict
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Duration specifies rule persistence
type Duration string

const (
	DurationOnce    Duration = "once"
	DurationSession Duration = "session"
	DurationAlways  Duration = "always"
)

// FirewallRule represents a user or system defined filtering rule
type FirewallRule struct {
	ID            string    `json:"id"`
	ProcessPath   string    `json:"process_path"`   // Exact path or "*" for any process
	ProcessName   string    `json:"process_name"`   // Friendly name e.g. "curl", "chrome"
	DomainPattern string    `json:"domain_pattern"` // e.g., "*.github.com", "api.stripe.com", "*"
	RemoteIP      string    `json:"remote_ip"`      // Specific IP, CIDR, or "*"
	RemotePort    int       `json:"remote_port"`    // Port number or 0 for any
	Protocol      string    `json:"protocol"`       // "tcp", "udp", "http", "tls", "*"
	Action        Action    `json:"action"`         // "allow" or "block"
	Duration      Duration  `json:"duration"`       // "once", "session", "always"
	CreatedAt     time.Time `json:"created_at"`
	HitCount      int64     `json:"hit_count"`
	LastHit       time.Time `json:"last_hit"`
	Comment       string    `json:"comment,omitempty"`
}

// RuleEngine handles in-memory lookup and disk persistence
type RuleEngine struct {
	mu           sync.RWMutex
	rules        map[string]*FirewallRule
	storagePath  string
	sessionRules map[string]*FirewallRule // Temporary rules discarded on daemon restart
	onceRules    map[string]*FirewallRule // Discarded after a single match
}

// NewRuleEngine initializes the engine and loads persisted rules from JSON
func NewRuleEngine(storagePath string) *RuleEngine {
	engine := &RuleEngine{
		rules:        make(map[string]*FirewallRule),
		sessionRules: make(map[string]*FirewallRule),
		onceRules:    make(map[string]*FirewallRule),
		storagePath:  storagePath,
	}

	if err := engine.loadFromDisk(); err != nil {
		log.Printf("[RuleEngine] Warning: Could not load rules from %s: %v. Initializing default rules.", storagePath, err)
		engine.seedDefaults()
	}

	return engine
}

// seedDefaults seeds essential system allow rules (e.g. localhost, DNS)
func (re *RuleEngine) seedDefaults() {
	re.mu.Lock()
	defer re.mu.Unlock()

	defaultRules := []*FirewallRule{
		{
			ID:            "rule-loopback-allow",
			ProcessPath:   "*",
			ProcessName:   "System",
			DomainPattern: "localhost",
			RemoteIP:      "127.0.0.1",
			RemotePort:    0,
			Protocol:      "*",
			Action:        ActionAllow,
			Duration:      DurationAlways,
			CreatedAt:     time.Now(),
			Comment:       "Allow all local loopback communication",
		},
		{
			ID:            "rule-dns-system-allow",
			ProcessPath:   "*",
			ProcessName:   "systemd-resolved",
			DomainPattern: "*",
			RemoteIP:      "*",
			RemotePort:    53,
			Protocol:      "udp",
			Action:        ActionAllow,
			Duration:      DurationAlways,
			CreatedAt:     time.Now(),
			Comment:       "Allow standard system DNS resolution",
		},
		{
			ID:            "rule-ntp-system-allow",
			ProcessPath:   "*",
			ProcessName:   "systemd-timesyncd",
			DomainPattern: "*.pool.ntp.org",
			RemoteIP:      "*",
			RemotePort:    123,
			Protocol:      "udp",
			Action:        ActionAllow,
			Duration:      DurationAlways,
			CreatedAt:     time.Now(),
			Comment:       "Allow network time sync",
		},
	}

	for _, r := range defaultRules {
		re.rules[r.ID] = r
	}
	re.saveToDiskUnsafe()
}

// Evaluate checks if an outbound connection matches any rule.
// Returns: Action ("allow" / "block" / "prompt"), matchingRule, and matched boolean.
func (re *RuleEngine) Evaluate(req *ConnectionRequest) (Action, *FirewallRule, bool) {
	re.mu.Lock()
	defer re.mu.Unlock()

	// 1. Check Once-Rules first
	for id, rule := range re.onceRules {
		if re.matchRule(rule, req) {
			rule.HitCount++
			rule.LastHit = time.Now()
			matched := *rule
			// Delete once rule after consuming
			delete(re.onceRules, id)
			log.Printf("[RuleEngine] Hit ONCE rule %s -> %s (consumed)", id, rule.Action)
			return rule.Action, &matched, true
		}
	}

	// 2. Check Session-Rules (in-memory)
	for _, rule := range re.sessionRules {
		if re.matchRule(rule, req) {
			rule.HitCount++
			rule.LastHit = time.Now()
			log.Printf("[RuleEngine] Hit SESSION rule %s -> %s", rule.ID, rule.Action)
			return rule.Action, rule, true
		}
	}

	// 3. Check Permanent Rules
	for _, rule := range re.rules {
		if re.matchRule(rule, req) {
			rule.HitCount++
			rule.LastHit = time.Now()
			log.Printf("[RuleEngine] Hit PERMANENT rule %s (%s) -> %s", rule.ID, rule.DomainPattern, rule.Action)
			return rule.Action, rule, true
		}
	}

	// No rule matched -> Needs UI prompt
	return "", nil, false
}

// matchRule verifies if connection request attributes satisfy rule criteria
func (re *RuleEngine) matchRule(rule *FirewallRule, req *ConnectionRequest) bool {
	// 1. Match Process
	if rule.ProcessPath != "*" && rule.ProcessPath != "" {
		if rule.ProcessPath != req.ProcessPath && !strings.EqualFold(rule.ProcessName, req.ProcessName) {
			return false
		}
	}

	// 2. Match Protocol
	if rule.Protocol != "*" && rule.Protocol != "" {
		if !strings.EqualFold(rule.Protocol, req.Protocol) {
			return false
		}
	}

	// 3. Match Remote Port
	if rule.RemotePort != 0 {
		if rule.RemotePort != req.RemotePort {
			return false
		}
	}

	// 4. Match Remote IP
	if rule.RemoteIP != "*" && rule.RemoteIP != "" {
		if rule.RemoteIP != req.RemoteIP {
			return false
		}
	}

	// 5. Match Domain Pattern (handles wildcards e.g. *.github.com)
	if rule.DomainPattern != "*" && rule.DomainPattern != "" {
		if !matchDomain(rule.DomainPattern, req.Domain) {
			return false
		}
	}

	return true
}

// matchDomain evaluates domain wildcard expressions like *.google.com, sub.domain.org, or exact match
func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if pattern == "*" || pattern == "" {
		return true
	}
	if domain == "" {
		return false
	}
	if pattern == domain {
		return true
	}

	// Prefix Wildcard e.g. "*.apple.com"
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".apple.com"
		if strings.HasSuffix(domain, suffix) {
			return true
		}
		// Also match exact root e.g. "apple.com" against "*.apple.com"
		if domain == pattern[2:] {
			return true
		}
	}

	// Suffix wildcard or glob
	matched, err := filepath.Match(pattern, domain)
	if err == nil && matched {
		return true
	}

	return false
}

// AddRule registers a new rule into the engine with specified persistence
func (re *RuleEngine) AddRule(rule *FirewallRule) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	if rule.ID == "" {
		rule.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}

	switch rule.Duration {
	case DurationOnce:
		re.onceRules[rule.ID] = rule
		log.Printf("[RuleEngine] Added ONCE rule: %+v", rule)
	case DurationSession:
		re.sessionRules[rule.ID] = rule
		log.Printf("[RuleEngine] Added SESSION rule: %+v", rule)
	case DurationAlways:
		re.rules[rule.ID] = rule
		log.Printf("[RuleEngine] Added ALWAYS rule: %+v", rule)
		return re.saveToDiskUnsafe()
	default:
		re.rules[rule.ID] = rule
		return re.saveToDiskUnsafe()
	}

	return nil
}

// DeleteRule removes a rule by ID across all buckets
func (re *RuleEngine) DeleteRule(id string) bool {
	re.mu.Lock()
	defer re.mu.Unlock()

	found := false
	if _, ok := re.rules[id]; ok {
		delete(re.rules, id)
		found = true
		_ = re.saveToDiskUnsafe()
	}
	if _, ok := re.sessionRules[id]; ok {
		delete(re.sessionRules, id)
		found = true
	}
	if _, ok := re.onceRules[id]; ok {
		delete(re.onceRules, id)
		found = true
	}

	return found
}

// GetAllRules returns a snapshot of all active rules
func (re *RuleEngine) GetAllRules() []*FirewallRule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	list := make([]*FirewallRule, 0, len(re.rules)+len(re.sessionRules)+len(re.onceRules))
	for _, r := range re.rules {
		list = append(list, r)
	}
	for _, r := range re.sessionRules {
		list = append(list, r)
	}
	for _, r := range re.onceRules {
		list = append(list, r)
	}
	return list
}

// loadFromDisk parses JSON rule database
func (re *RuleEngine) loadFromDisk() error {
	re.mu.Lock()
	defer re.mu.Unlock()

	file, err := os.Open(re.storagePath)
	if err != nil {
		return err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var storedRules []*FirewallRule
	if err := json.Unmarshal(bytes, &storedRules); err != nil {
		return err
	}

	re.rules = make(map[string]*FirewallRule)
	for _, r := range storedRules {
		re.rules[r.ID] = r
	}

	log.Printf("[RuleEngine] Loaded %d rules from %s", len(re.rules), re.storagePath)
	return nil
}

// saveToDiskUnsafe persists permanent rules to disk (must be called with Lock held)
func (re *RuleEngine) saveToDiskUnsafe() error {
	list := make([]*FirewallRule, 0, len(re.rules))
	for _, r := range re.rules {
		list = append(list, r)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(re.storagePath, data, 0600)
}
