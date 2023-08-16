package main

import (
	"flag"
	"log"

	"github.com/nighttardis/sigma_crowdstrike_ioa/utilities"
)

func main() {
	configPath := flag.String("config-path", "config.yaml", "Path to configuration file")
	sigmaRule := flag.String("sigma-rule", "", "Path to a single Simga Rule you wish to convert")
	sigmaPath := flag.String("sigma-path", "", "Path to directory of Sigma Rules you wish to convert")

	flag.Parse()

	if *sigmaRule == "" && *sigmaPath == "" {
		log.Fatal("sigma-rule or sigma-path must be provided")
	} else if *sigmaRule != "" && *sigmaPath != "" {
		log.Fatal("Provided both sigma-rule and sigma-path, please only provide one or the other")
	}

	a := utilities.LoadConfig(*configPath)
	//cs_client = a.Authenticate()
	a.Authenticate()

	// fmt.Println(a.Mappings["process_creation"])

	if *sigmaRule != "" {
		utilities.ParseRule(*sigmaRule, a)
	} else if *sigmaPath != "" {
		utilities.ParseRuleDirectory(*sigmaPath, a)
	}
}
