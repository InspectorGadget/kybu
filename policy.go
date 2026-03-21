package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/InspectorGadget/kybu/variables"
)

var reSidSanitizer = regexp.MustCompile(`[^a-zA-Z0-9]`)

func generateJSON() string {
	type Statement struct {
		Sid      string   `json:"Sid"`
		Effect   string   `json:"Effect"`
		Action   []string `json:"Action"`
		Resource []string `json:"Resource"`
	}
	type Policy struct {
		Version   string      `json:"Version"`
		Statement []Statement `json:"Statement"`
	}

	final := Policy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	var actions []string
	for action := range variables.Policy.Data {
		actions = append(actions, action)
	}
	sort.Strings(actions)

	for _, action := range actions {
		resourcesMap := variables.Policy.Data[action]
		var resources []string
		for resource := range resourcesMap {
			resources = append(resources, resource)
		}
		sort.Strings(resources)

		final.Statement = append(final.Statement, Statement{
			Sid:      sidFromAction(action),
			Effect:   "Allow",
			Action:   []string{action},
			Resource: resources,
		})
	}

	bytes, _ := json.MarshalIndent(final, "", "    ")
	return string(bytes)
}

func sidFromAction(action string) string {
	if action == "" {
		return "AllowUnknown"
	}
	parts := strings.Split(action, ":")
	service := strings.ToUpper(parts[0])
	operation := ""
	if len(parts) > 1 {
		operation = parts[1]
	}
	cleanOperation := reSidSanitizer.ReplaceAllString(operation, "")
	if cleanOperation == "" {
		return "Allow" + service
	}
	return "Allow" + service + cleanOperation
}
