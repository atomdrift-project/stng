package main

import "fmt"

// These strings will be obfuscated by garble -literals
var secretURL = "https://malware.example.com/callback"
var secretPath = "/etc/shadow"
var secretCmd = "curl -X POST"
var secretKey = "AKIA1234567890ABCDEF"

func main() {
	fmt.Println(secretURL)
	fmt.Println(secretPath)
	fmt.Println(secretCmd)
	fmt.Println(secretKey)
}
