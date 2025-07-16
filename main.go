package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ed25519"
	"github.com/mikesmitty/edkey"
)


// GenerateEd25519 key
func GenerateEd25519Key(passphrase string) ed25519.PrivateKey {
	hash := sha256.Sum256([]byte(passphrase))
	return ed25519.NewKeyFromSeed(hash[:])
}


func main() {
	// Input passphrase
	fmt.Print("Enter a passphrase for your brain ssh, make sure it's easy to remember but hard for other to guess: ")
	var passphrase string
	fmt.Scanln(&passphrase)
	if len(passphrase) < 32 {
		fmt.Println("Too short, at least 32 characters please")
		os.Exit(1)
	}

	// Generate private key
	privateKey := GenerateEd25519Key(passphrase)
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate public key
	pubKey := privateKey.Public().(ed25519.PublicKey)
	publicKey, _ := ssh.NewPublicKey(pubKey)

	//fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(publicKey))

	// Marshal the private key to OpenSSH format using edkey and wrap in PEM
	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateKey),
	}
	privateKeyPEM := pem.EncodeToMemory(pemKey)
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	// save key pair to files
	currentUser, _ := user.Current()
	homeDir := currentUser.HomeDir
	pri := filepath.Join(homeDir, ".ssh", "id_ed25519")
	pub := filepath.Join(homeDir, ".ssh", "id_ed25519.pub")
	fmt.Println("pri (OpenSSH format):", pri)
	fmt.Println("pub:", pub)
	os.WriteFile(pri, privateKeyPEM, 0600)
	os.WriteFile(pub, publicKeyBytes, 0644)
	fmt.Println("\nYou can now add the public key to GitHub and use the private key for SSH authentication.")
}
// add pubkey to github
// ssh -T -p 443 git@ssh.github.com

