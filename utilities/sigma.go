package utilities

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/markuskont/go-sigma-rule-engine"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var validOS = []string{"windows", "macos", "linux"}

var dispositionID = map[string]int32{"monitor": int32(0), "detect": int32(1), "kill_process": int32(2), "block_write": int32(2)}

var patternSeverity = []string{"informational", "low", "medium", "high", "critial"}

var csMapping = map[string]string{"image": "ImageFileName", "commandline": "CommandLine", "targetfilename": "TargetFilename"}

func handleCriteria(values interface{}) string {
	var returnString string

	switch y := values.(type) {
	case []interface{}:
		for _, z := range y {
			if returnString == "" {
				returnString = regexp.QuoteMeta(z.(string))
			} else {
				returnString = returnString + "|" + regexp.QuoteMeta(z.(string))
			}
		}
	case string:
		returnString = regexp.QuoteMeta(values.(string))
	default:
		log.Printf("Unexpected type of %s", reflect.TypeOf(y))
		return ""
	}

	return returnString
}

func handleModifier(modifier string, values interface{}) *string {

	// need to handle the modifier "all" for lists
	// may need some extra work to escape "/" if there are issues

	var returnString string

	returnString = handleCriteria(values)
	if returnString == "" {
		return new(string)
	}

	switch strings.ToLower(modifier) {
	case "contains":
		returnString = ".*(" + returnString + ").*"
	case "re":
		// leaving this hear incase there is something that needs to be done for re
	case "startswith":
		returnString = "(" + returnString + ").*"
	case "endswith":
		returnString = ".*(" + returnString + ")"
	default:
		log.Printf("Unsupport modifier %s", modifier)
		return new(string)
	}

	return &returnString
}

type ruleParsed struct {
	Predicate   string
	ParsedEntry *string
}

func handleRule(value map[interface{}]interface{}) []ruleParsed {

	var predicate string
	var modifier string
	var parsedEntry *string
	var rulesParsed []ruleParsed

	for i, v := range value {
		predicate = i.(string)
		if strings.Contains(predicate, "|") {
			tmpMod := strings.Split(predicate, "|")
			modifier = tmpMod[len(tmpMod)-1]
			predicate = tmpMod[0]
		}
		if !(slices.Contains(maps.Keys(csMapping), strings.ToLower(predicate))) {
			log.Printf("Unknown fieldname %s", predicate)
			continue
		}

		if modifier != "" {
			parsedEntry = handleModifier(modifier, v)
		} else {
			parsedEntry = convertString(handleCriteria(v))
		}
		rulesParsed = append(rulesParsed, ruleParsed{
			Predicate:   predicate,
			ParsedEntry: parsedEntry,
		})
	}
	return rulesParsed
}

func parseRule(ruleset []sigma.RuleHandle, c *Config) {

	// var predicate string
	// var parsedEntry *string
	var rulesParsed []ruleParsed

	for _, rule := range ruleset {
		var CSRule models.APIRuleCreateV1
		var CSRuleValues []*models.DomainFieldValue
		var CSDVIs []*models.DomainValueItem

		//This likely will need to be updated/changed to handle entries where there is no product
		//Example: https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_susp_txt_exec_strings.yml
		if !(slices.Contains(validOS, strings.ToLower(rule.Logsource.Product))) {
			log.Fatalf("Unknown OS/Product: %s", rule.Logsource.Product)
		}

		// This would be great to fix in the future but not a priority right now
		if strings.Contains(strings.ToLower(rule.Detection["condition"].(string)), " and ") || strings.Contains(strings.ToLower(rule.Detection["condition"].(string)), " or ") ||
			strings.Contains(strings.ToLower(rule.Detection["condition"].(string)), " not ") {
			fmt.Printf("Complex conditions aren't allowed for now. Skipping %s", rule.Path)
			continue
		}

		var csRuleDescription = rule.Description + "\nRule Author: " + rule.Author + "\nRule Source: " + rule.Path

		CSRule.Description = &csRuleDescription

		CSRule.Name = &rule.Title

		CSRule.DispositionID = new(int32)

		CSRule.PatternSeverity = &patternSeverity[0]

		// This needs to be looked up using the CS Client
		// Also need to deside how to identify this, likely will use a tag like
		//		cs.<group_name>
		CSRule.RulegroupID = new(string)

		// This needs to be looked up using the CS Client
		// Need to understand what this actually means as it may need to be set within the switch statement for the different
		// rule.Logsource.Category
		CSRule.RuletypeID = new(string)

		if slices.Contains(patternSeverity, strings.ToLower(rule.Level)) {
			CSRule.PatternSeverity = convertString(strings.ToLower(rule.Level))
		} else {
			log.Printf("Unknown rule level %s setting to default \"informational\"", strings.ToLower(rule.Level))
		}

		switch strings.ToLower(rule.Logsource.Category) {
		case "process_creation":
			fmt.Println("process_creation")

			if slices.Contains(maps.Keys(c.Mappings), strings.ToLower(rule.Logsource.Category)) {
				if slices.Contains(maps.Keys(c.Mappings[strings.ToLower(rule.Logsource.Category)]), strings.ToLower(rule.Status)) {
					CSRule.DispositionID = func(i int32) *int32 { return &i }(dispositionID[c.Mappings[strings.ToLower(rule.Logsource.Category)][strings.ToLower(rule.Status)]])
				} else {
					log.Printf("Uknown mapping for %s for %s setting Disposition to 0", rule.Status, rule.Logsource.Category)
				}
			} else {
				log.Printf("Uknown mapping for %s setting Disposition to 0", rule.Logsource.Category)
			}

			for _, detect_con := range rule.Detection.Extract() {

				switch x := detect_con.(type) {
				case []interface{}:
					for _, v := range x {
						rulesParsed = handleRule(v.(map[interface{}]interface{}))
						for _, rule := range rulesParsed {
							if rule.Predicate == "" {
								continue
							}
							// need to figure out what labal and value actually mean
							CSDVIs = append(CSDVIs, &models.DomainValueItem{
								Label: convertString(csMapping[strings.ToLower(rule.Predicate)]),
								Value: rule.ParsedEntry,
							})
						}
					}
				case map[interface{}]interface{}:
					rulesParsed = handleRule(detect_con.(map[interface{}]interface{}))
					for _, rule := range rulesParsed {
						if rule.Predicate == "" {
							continue
						}
						// need to figure out what labal and value actually mean
						CSDVIs = append(CSDVIs, &models.DomainValueItem{
							Label: convertString(csMapping[strings.ToLower(rule.Predicate)]),
							Value: rule.ParsedEntry,
						})
					}
				default:
					log.Printf("Unsupported %s", reflect.TypeOf(x))
					continue
				}

			}
		case "network_connection":
			fmt.Println("network_connection.\nThis is not implemented yet.")
		case "dns_query":
			fmt.Println("dns_query.\nThis is not implemented yet.")
		case "file_event":
			fmt.Println("file_event")
			if slices.Contains(maps.Keys(c.Mappings), strings.ToLower(rule.Logsource.Category)) {
				if slices.Contains(maps.Keys(c.Mappings[strings.ToLower(rule.Logsource.Category)]), strings.ToLower(rule.Status)) {
					CSRule.DispositionID = func(i int32) *int32 { return &i }(dispositionID[c.Mappings[strings.ToLower(rule.Logsource.Category)][strings.ToLower(rule.Status)]])
				} else {
					log.Printf("Uknown mapping for %s for %s setting Disposition to 0", rule.Status, rule.Logsource.Category)
				}
			} else {
				log.Printf("Uknown mapping for %s setting Disposition to 0", rule.Logsource.Category)
			}

			for _, detect_con := range rule.Detection.Extract() {

				switch x := detect_con.(type) {
				case []interface{}:
					for _, v := range x {
						rulesParsed = handleRule(v.(map[interface{}]interface{}))
						for _, rule := range rulesParsed {
							if rule.Predicate == "" {
								continue
							}
							// need to figure out what labal and value actually mean
							CSDVIs = append(CSDVIs, &models.DomainValueItem{
								Label: convertString(csMapping[strings.ToLower(rule.Predicate)]),
								Value: rule.ParsedEntry,
							})
						}
					}
				case map[interface{}]interface{}:
					rulesParsed = handleRule(detect_con.(map[interface{}]interface{}))
					for _, rule := range rulesParsed {
						if rule.Predicate == "" {
							continue
						}
						// need to figure out what labal and value actually mean
						CSDVIs = append(CSDVIs, &models.DomainValueItem{
							Label: convertString(csMapping[strings.ToLower(rule.Predicate)]),
							Value: rule.ParsedEntry,
						})
					}
				default:
					log.Printf("Unsupported %s", reflect.TypeOf(x))
					continue
				}
			}
		default:
			log.Printf("Unsupport category %s", strings.ToLower(rule.Logsource.Category))
			continue
		}

		if len(CSDVIs) > 0 {
			// Need to figure out what these values should actually be
			CSRuleValues = append(CSRuleValues, &models.DomainFieldValue{
				Name:   convertString("idk"),
				Type:   convertString("idk"),
				Value:  convertString("idk"),
				Values: CSDVIs,
			})
		}

		CSRule.FieldValues = CSRuleValues

		b, _ := json.Marshal(CSRule)

		fmt.Println(string(b))
	}
}

func ParseRule(rulePath string, c *Config) {
	ruleset, err := sigma.NewRuleList([]string{rulePath}, false, false)

	if err != nil {
		log.Printf("Unable to load rules from %s\n", rulePath)
		log.Fatal(err)
	}

	parseRule(ruleset, c)

}

func ParseRuleDirectory(rulePath string, c *Config) {
	ruleset, err := sigma.NewRuleFileList([]string{rulePath})

	if err != nil {
		log.Printf("Unable to load rules from %s\n", rulePath)
		log.Fatal(err)
	}

	for _, f := range ruleset {
		ParseRule(f, c)
	}
}
