package main

import (
	//"crypto/rand"
	"crypto/sha256"
	"crypto/ed25519"
	"encoding/pem"
	"encoding/hex"
	"crypto/x509"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"github.com/ScaleFT/sshkeys"
)


// GeneratePrivateKey generates a private key using SHA256 on the given passphrase
func GeneratePrivateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

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
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(publicKey))

	//// ssh format public key
	sshPublicKey, _ := ssh.NewPublicKey(publicKey)
	fmt.Printf("SSH Public Key (hex): %s\n", hex.EncodeToString(sshPublicKey.Marshal()))
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)

	// save key pair to files
	currentUser, _ := user.Current()
	homeDir := currentUser.HomeDir
	pri := filepath.Join(homeDir, ".ssh", "id_ed25519")
	pub := filepath.Join(homeDir, ".ssh", "id_ed25519.pub")

	fmt.Println("pri:", pri)
	fmt.Println("pub:", pub)

	// Marshal the private key to OpenSSH format using sshkeys
	privBytes, err := sshkeys.MarshalED25519PrivateKey(privateKey, "")
	if err != nil {
		panic(err)
	}
	os.WriteFile(pri, privBytes, 0600)
	os.WriteFile(pub, publicKeyBytes, 0644)
}

