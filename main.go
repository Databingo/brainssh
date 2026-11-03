package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

// GenerateEd25519 key (完全保持你的原逻辑)
func GenerateEd25519Key(passphrase string) ed25519.PrivateKey {
	hash := sha256.Sum256([]byte(passphrase))
	return ed25519.NewKeyFromSeed(hash[:])
}

func main() {
	fmt.Print("Enter a passphrase for your brain ssh (spaces allowed) pure ascii: ")

	// 【修复空格】：使用 bufio 读取整行，支持任意空格
	reader := bufio.NewReader(os.Stdin)
	passphrase, _ := reader.ReadString('\n')
	passphrase = strings.TrimRight(passphrase, "\r\n")

	if len(passphrase) < 32 {
		fmt.Printf("Too short (current length: %d), at least 32 characters please\n", len(passphrase))
		os.Exit(1)
	}

	// Generate private key
	privateKey := GenerateEd25519Key(passphrase)
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate public key
	pubKey := privateKey.Public().(ed25519.PublicKey)
	publicKey, _ := ssh.NewPublicKey(pubKey)

	// Marshal the private key to OpenSSH format using edkey and wrap in PEM
	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateKey),
	}
	privateKeyPEM := pem.EncodeToMemory(pemKey)
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	keyName := "id_ed25519_" + hex.EncodeToString(pubKey[:4])
	pri := filepath.Join(homeDir, ".ssh", keyName)
	pub := filepath.Join(homeDir, ".ssh", keyName+".pub")

	fmt.Println("pri (OpenSSH format):", pri)
	fmt.Println("pub:", pub)
	os.WriteFile(pri, privateKeyPEM, 0600)
	os.WriteFile(pub, publicKeyBytes, 0644)

	fmt.Println("\nYou can now add the public key to GitHub and use the private key for SSH authentication.")
}
// 1.add pubkey to github
// 2.test: ssh -T -p 443 git@ssh.github.com

