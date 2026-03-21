package main

import (
	"regexp"
	"strings"
)

var reListBucketWord = regexp.MustCompile(`\bListBucket\b`)

func inferActionFromError(msg string, fallback string) string {
	lower := strings.ToLower(msg)

	if strings.Contains(msg, "ListBuckets") {
		return "s3:ListAllMyBuckets"
	}
	if strings.Contains(msg, "ListObjectsV2") || reListBucketWord.MatchString(msg) || strings.Contains(lower, "nosuchbucket") {
		return "s3:ListBucket"
	}
	if strings.Contains(msg, "PutObject") {
		return "s3:PutObject"
	}
	if strings.Contains(msg, "GetObject") {
		return "s3:GetObject"
	}
	if strings.Contains(msg, "DescribeTable") {
		return "dynamodb:DescribeTable"
	}

	return fallback
}

func inferActionFromCliArgs(args []string) string {
	if len(args) < 2 {
		return ""
	}
	service := strings.ToLower(strings.TrimSpace(args[0]))
	command := strings.ToLower(strings.TrimSpace(args[1]))

	if service == "s3" && command == "ls" {
		for _, arg := range args[2:] {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(arg)), "s3://") {
				return "s3:ListBucket"
			}
		}
		return "s3:ListAllMyBuckets"
	}

	return ""
}

func shouldSuppressWildcard(action string, resources []string) bool {
	if len(resources) > 0 {
		return false
	}
	lowerAction := strings.ToLower(strings.TrimSpace(action))
	return lowerAction == "s3:listbucket"
}

func renderResources(resources []string, suppressWildcard bool) string {
	if len(resources) > 0 {
		return strings.Join(resources, ", ")
	}
	if suppressWildcard {
		return "(resource unresolved; wildcard suppressed)"
	}
	return "*"
}

func isIdentityArn(arn string) bool {
	identityMarkers := []string{":iam::", ":sts::", ":user/", ":role/", "assumed-role/"}
	for _, marker := range identityMarkers {
		if strings.Contains(arn, marker) {
			return true
		}
	}
	return false
}

func applyServiceRules(action string, arn string) string {
	if !strings.HasPrefix(action, "s3:") || arn == "*" {
		return arn
	}

	objectActions := []string{"GetObject", "PutObject", "DeleteObject", "AbortMultipartUpload"}
	isObjectAction := false
	for _, oa := range objectActions {
		if strings.Contains(action, oa) {
			isObjectAction = true
			break
		}
	}

	if isObjectAction && !strings.Contains(arn, "/") {
		return strings.TrimSuffix(arn, "/") + "/*"
	}

	bucketActions := []string{"ListBucket", "GetBucketLocation"}
	for _, ba := range bucketActions {
		if strings.Contains(action, ba) {
			return strings.Split(arn, "/")[0]
		}
	}

	return arn
}
