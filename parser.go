package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/InspectorGadget/kybu/structs"
)

var (
	reTableName           = regexp.MustCompile(`Table:\s+([a-zA-Z0-9._-]+)`)
	reS3FromMessage       = regexp.MustCompile(`(?:s3://|bucket\s+)([a-zA-Z0-9.-]+)`)
	reS3BucketNameText    = regexp.MustCompile(`(?i)bucketname\s*:\s*([a-z0-9.-]+)`)
	reS3BucketNameJSON    = regexp.MustCompile(`(?i)"bucketname"\s*:\s*"([a-z0-9.-]+)"`)
	reS3BucketNameLoose   = regexp.MustCompile(`(?i)\bbucketname\b\s*[:=]?\s*"?([a-z0-9.-]+)"?`)
	reS3HistoryLS         = regexp.MustCompile(`(?i)aws\s+s3\s+ls\s+s3://([a-z0-9.-]+)`)
	reS3HistoryListObject = regexp.MustCompile(`(?i)aws\s+s3api\s+list-objects-v2\s+--bucket\s+([a-z0-9.-]+)`)
	reLikelyS3BucketName  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
)

func normalizeErrorSnippets(packet structs.CSMPacket) ([]string, []string) {
	fragments := []string{
		packet.RawPacket,
		packet.AwsExceptionMessage,
		packet.Message,
		packet.ErrorMessage,
		packet.AwsException,
	}
	var parts []string
	var cliArgs []string
	for _, fragment := range fragments {
		normalized := stripAwsErrorPrefix(fragment)
		if normalized == "" {
			continue
		}
		parts = append(parts, normalized)
		parts = append(parts, expandStructuredSnippet(normalized)...)
		cliArgs = append(cliArgs, extractCliArguments(normalized)...)
	}
	return uniqueStrings(parts), uniqueStrings(cliArgs)
}

func stripAwsErrorPrefix(fragment string) string {
	trimmed := strings.TrimSpace(fragment)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	prefixes := []string{"aws: [error]:", "aws: error:", "aws error:"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return trimmed
}

func expandStructuredSnippet(snippet string) []string {
	text := strings.TrimSpace(snippet)
	if text == "" || !strings.HasPrefix(text, "{") {
		return nil
	}
	var payload interface{}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return nil
	}
	var acc []string
	collectStringLeaves(payload, &acc)
	return acc
}

func extractCliArguments(snippet string) []string {
	text := strings.TrimSpace(snippet)
	if text == "" || !strings.HasPrefix(text, "{") {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil
	}

	ctxRaw, ok := raw["context"]
	if !ok {
		ctxRaw, ok = raw["Context"]
	}
	if !ok {
		return nil
	}
	ctxMap, ok := ctxRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	argsRaw, ok := ctxMap["arguments"]
	if !ok {
		argsRaw, ok = ctxMap["Arguments"]
	}
	if !ok {
		return nil
	}

	arr, ok := argsRaw.([]interface{})
	if !ok {
		return nil
	}

	args := make([]string, 0, len(arr))
	for _, item := range arr {
		if textItem, ok := item.(string); ok {
			args = append(args, strings.TrimSpace(textItem))
		}
	}
	return uniqueStrings(args)
}

func deriveResourcesFromCliArgs(args []string, region string) []string {
	if len(args) == 0 {
		return nil
	}
	if region == "" {
		region = "us-east-1"
	}

	var resources []string
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if strings.HasPrefix(arg, "arn:") {
			resources = append(resources, arg)
			continue
		}
		if strings.HasPrefix(strings.ToLower(arg), "s3://") {
			if arn := s3URIToArn(arg); arn != "" {
				resources = append(resources, arn)
			}
			continue
		}

		flagName, inlineValue := splitFlagAndValue(arg)
		if flagName == "" {
			continue
		}
		value := inlineValue
		if value == "" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			value = args[i+1]
			i++
		}
		if candidate := resourceFromFlag(flagName, value, region); candidate != "" {
			resources = append(resources, candidate)
		}
	}
	return uniqueStrings(resources)
}

func splitFlagAndValue(arg string) (string, string) {
	if !strings.HasPrefix(arg, "--") {
		return "", ""
	}
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return arg, ""
}

func resourceFromFlag(flag string, value string, region string) string {
	if flag == "" {
		return ""
	}
	cleanFlag := strings.TrimLeft(strings.ToLower(flag), "-")
	sanitized := sanitizeCliValue(value)
	if sanitized == "" {
		return ""
	}

	switch cleanFlag {
	case "table-name":
		return fmt.Sprintf("arn:aws:dynamodb:%s:*:table/%s", region, sanitized)
	case "bucket", "source-bucket", "destination-bucket", "bucket-name":
		return bucketNameToArn(sanitized)
	}

	if strings.HasSuffix(cleanFlag, "-arn") && strings.HasPrefix(sanitized, "arn:") {
		return sanitized
	}
	return ""
}

func bucketNameToArn(value string) string {
	if strings.HasPrefix(value, "arn:") {
		return value
	}
	if strings.HasPrefix(strings.ToLower(value), "s3://") {
		return s3URIToArn(value)
	}
	trimmed := strings.Trim(value, "/")
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:s3:::%s", trimmed)
}

func s3URIToArn(uri string) string {
	trimmed := strings.TrimSpace(uri)
	trimmed = strings.TrimPrefix(trimmed, "s3://")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	bucket := parts[0]
	if bucket == "" {
		return ""
	}
	if len(parts) == 1 {
		return fmt.Sprintf("arn:aws:s3:::%s", bucket)
	}
	key := strings.Trim(parts[1], "/")
	if key == "" {
		return fmt.Sprintf("arn:aws:s3:::%s", bucket)
	}
	return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key)
}

func sanitizeCliValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.Trim(trimmed, "\"'")
	return trimmed
}

func collectStringLeaves(value interface{}, acc *[]string) {
	switch typed := value.(type) {
	case string:
		candidate := strings.TrimSpace(typed)
		if candidate != "" {
			*acc = append(*acc, candidate)
		}
	case []interface{}:
		for _, item := range typed {
			collectStringLeaves(item, acc)
		}
	case map[string]interface{}:
		for key, val := range typed {
			cleanKey := strings.TrimSpace(key)
			if cleanKey != "" {
				*acc = append(*acc, cleanKey)
			}
			collectStringLeaves(val, acc)
		}
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range values {
		clean := strings.TrimSpace(v)
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		result = append(result, clean)
	}
	return result
}

func deriveResourcesFromRawPacket(raw string) []string {
	text := strings.TrimSpace(raw)
	if text == "" || !strings.HasPrefix(text, "{") {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return nil
	}
	var resources []string
	collectResourcesFromRawValue(payload, &resources)
	return uniqueStrings(resources)
}

func collectResourcesFromRawValue(value interface{}, resources *[]string) {
	switch typed := value.(type) {
	case string:
		candidate := strings.TrimSpace(typed)
		if candidate == "" {
			return
		}
		if strings.HasPrefix(strings.ToLower(candidate), "s3://") {
			if arn := s3URIToArn(candidate); arn != "" {
				*resources = append(*resources, arn)
			}
		}
		if strings.HasPrefix(candidate, "arn:") {
			*resources = append(*resources, candidate)
		}
	case []interface{}:
		for _, item := range typed {
			collectResourcesFromRawValue(item, resources)
		}
	case map[string]interface{}:
		for childKey, childValue := range typed {
			lowerKey := strings.ToLower(strings.TrimSpace(childKey))
			if text, ok := childValue.(string); ok {
				candidate := strings.TrimSpace(text)
				if lowerKey == "bucket" || lowerKey == "bucketname" || lowerKey == "bucket_name" {
					if arn := bucketNameToArn(candidate); arn != "" {
						*resources = append(*resources, arn)
					}
				}
				if lowerKey == "fqdn" || lowerKey == "host" || lowerKey == "hostname" || lowerKey == "endpoint" {
					if bucket := bucketFromS3FQDN(candidate); bucket != "" {
						if arn := bucketNameToArn(bucket); arn != "" {
							*resources = append(*resources, arn)
						}
					}
				}
				if lowerKey == "uri" || lowerKey == "path" || lowerKey == "requesturi" || lowerKey == "canonicaluri" || lowerKey == "request_uri" {
					if bucket := bucketFromS3Path(candidate); bucket != "" {
						if arn := bucketNameToArn(bucket); arn != "" {
							*resources = append(*resources, arn)
						}
					}
				}
			}
			collectResourcesFromRawValue(childValue, resources)
		}
	}
}

func deriveResourcesFromShellHistory(action string) []string {
	if strings.ToLower(strings.TrimSpace(action)) != "s3:listbucket" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	historyPaths := []string{
		filepath.Join(home, ".local", "share", "fish", "fish_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".bash_history"),
	}
	for _, path := range historyPaths {
		if resources := extractS3ResourcesFromHistoryFile(path); len(resources) > 0 {
			return resources
		}
	}
	return nil
}

func extractS3ResourcesFromHistoryFile(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(content)
	var buckets []string
	for _, match := range reS3HistoryLS.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			buckets = append(buckets, match[1])
		}
	}
	for _, match := range reS3HistoryListObject.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			buckets = append(buckets, match[1])
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	lastBucket := strings.TrimSpace(buckets[len(buckets)-1])
	if lastBucket == "" {
		return nil
	}
	arn := bucketNameToArn(lastBucket)
	if arn == "" {
		return nil
	}
	return []string{arn}
}

func bucketFromS3FQDN(fqdn string) string {
	host := strings.ToLower(strings.TrimSpace(fqdn))
	host = strings.Trim(host, ".")
	if host == "" || !strings.Contains(host, ".s3.") {
		return ""
	}
	parts := strings.SplitN(host, ".s3.", 2)
	if len(parts) != 2 {
		return ""
	}
	bucket := strings.TrimSpace(parts[0])
	if bucket == "" || bucket == "s3" {
		return ""
	}
	return bucket
}

func bucketFromS3Path(uri string) string {
	path := strings.TrimSpace(uri)
	if path == "" {
		return ""
	}
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	bucket := strings.SplitN(trimmed, "/", 2)[0]
	if !isLikelyS3BucketName(bucket) {
		return ""
	}
	return bucket
}

func isLikelyS3BucketName(value string) bool {
	bucket := strings.TrimSpace(strings.ToLower(value))
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}
	if strings.HasPrefix(bucket, ".") || strings.HasSuffix(bucket, ".") || strings.HasPrefix(bucket, "-") || strings.HasSuffix(bucket, "-") {
		return false
	}
	return reLikelyS3BucketName.MatchString(bucket)
}
