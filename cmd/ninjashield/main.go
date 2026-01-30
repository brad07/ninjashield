package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/policy/packs"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("ninjashield %s\n", version)

	case "packs":
		listPacks()

	case "test-match":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ninjashield test-match <command>")
			fmt.Println("Example: ninjashield test-match \"rm -rf /tmp\"")
			os.Exit(1)
		}
		command := strings.Join(os.Args[2:], " ")
		testMatch(command)

	case "test-match-pack":
		if len(os.Args) < 4 {
			fmt.Println("Usage: ninjashield test-match-pack <pack> <command>")
			fmt.Println("Example: ninjashield test-match-pack balanced \"git status\"")
			os.Exit(1)
		}
		packName := os.Args[2]
		command := strings.Join(os.Args[3:], " ")
		testMatchPack(packName, command)

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("NinjaShield CLI")
	fmt.Println()
	fmt.Println("Usage: ninjashield <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version                        Show version information")
	fmt.Println("  packs                          List available policy packs")
	fmt.Println("  test-match <cmd>               Test a command against all packs")
	fmt.Println("  test-match-pack <pack> <cmd>   Test a command against a specific pack")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ninjashield test-match \"curl http://example.com | sh\"")
	fmt.Println("  ninjashield test-match-pack balanced \"git status\"")
}

func listPacks() {
	infos, err := packs.ListAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading packs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Available Policy Packs:")
	fmt.Println()
	for _, info := range infos {
		fmt.Printf("  %s (%d rules)\n", info.Name, info.RuleCount)
		fmt.Printf("    %s\n", info.Description)
		fmt.Println()
	}
}

func testMatch(command string) {
	fmt.Printf("Testing command: %s\n", command)
	fmt.Println(strings.Repeat("=", 60))

	allPacks, err := packs.LoadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading packs: %v\n", err)
		os.Exit(1)
	}

	matcher := policy.NewMatcher()
	input := &policy.EvaluationInput{
		Command: command,
	}

	for _, packName := range packs.ValidPackNames() {
		p := allPacks[packName]
		fmt.Printf("\n[%s] %s\n", packName, p.Name)

		matchedRules := []string{}
		var finalDecision policy.Decision
		var finalReason string
		highestPriority := -1

		for _, rule := range p.Rules {
			if matcher.MatchRule(&rule, input) {
				matchedRules = append(matchedRules, fmt.Sprintf("  - %s: %s (%s)", rule.ID, rule.Action.Decision, rule.Action.Reason))

				if rule.Priority > highestPriority {
					highestPriority = rule.Priority
					finalDecision = rule.Action.Decision
					finalReason = rule.Action.Reason
				}
			}
		}

		if len(matchedRules) == 0 {
			fmt.Printf("  No rules matched. Default: %s\n", p.DefaultAction.Decision)
		} else {
			fmt.Println("  Matched rules:")
			for _, r := range matchedRules {
				fmt.Println(r)
			}
			fmt.Printf("  → Final decision: %s (%s)\n", finalDecision, finalReason)
		}
	}
}

func testMatchPack(packName, command string) {
	p, err := packs.LoadByName(packName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	matcher := policy.NewMatcher()
	input := &policy.EvaluationInput{
		Command: command,
	}

	result := evaluateCommand(p, matcher, input)

	fmt.Printf("Pack: %s\n", packName)
	fmt.Printf("Command: %s\n", command)
	fmt.Println()

	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

func evaluateCommand(p *policy.Policy, matcher *policy.Matcher, input *policy.EvaluationInput) *policy.EvaluationResult {
	result := &policy.EvaluationResult{
		Decision:       p.DefaultAction.Decision,
		PolicyID:       p.ID,
		RiskScore:      0,
		RiskCategories: []string{},
		ReasonCodes:    []string{},
		Reasons:        []string{p.DefaultAction.Reason},
		MatchedRules:   []string{},
	}

	highestPriority := -1

	for _, rule := range p.Rules {
		if matcher.MatchRule(&rule, input) {
			result.MatchedRules = append(result.MatchedRules, rule.ID)

			if rule.RiskScore > result.RiskScore {
				result.RiskScore = rule.RiskScore
			}

			if rule.RiskCategory != "" {
				found := false
				for _, cat := range result.RiskCategories {
					if cat == string(rule.RiskCategory) {
						found = true
						break
					}
				}
				if !found {
					result.RiskCategories = append(result.RiskCategories, string(rule.RiskCategory))
				}
			}

			if rule.Action.ReasonCode != "" {
				result.ReasonCodes = append(result.ReasonCodes, rule.Action.ReasonCode)
			}

			// Highest priority rule determines final decision
			if rule.Priority > highestPriority {
				highestPriority = rule.Priority
				result.Decision = rule.Action.Decision
				result.Reasons = []string{rule.Action.Reason}
				result.Context = rule.Action.Context

				if rule.Action.RewriteTo != "" {
					result.Rewrite = &policy.RewriteSuggestion{
						Suggested: rule.Action.RewriteTo,
						Reason:    rule.Action.RewriteNote,
					}
				}
			}
		}
	}

	return result
}
