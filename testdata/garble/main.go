package main

import "fmt"

// These strings will be obfuscated by garble -literals
var secretURL = "https://malware.example.com/callback"
var secretPath = "/etc/shadow"
var secretCmd = "curl -X POST"
var secretKey = "AKIA1234567890ABCDEF"
var envVar = "SECRET_TOKEN"
var configPath = "/var/lib/malware/config.json"

func main() {
	fmt.Println(secretURL)
	fmt.Println(secretPath)
	fmt.Println(secretCmd)
	fmt.Println(secretKey)
	fmt.Println(envVar)
	fmt.Println(configPath)
}
