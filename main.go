package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/ed25519"
	"encoding/pem"
	"encoding/hex"
	"encoding/binary"
	"fmt"
	//"log"
	"os"

	"golang.org/x/crypto/ssh"
	//"github.com/mikesm_org/ed25519-pkcs8"
	//"golang.org/x/term"
)


// GeneratePrivateKey generates a private key using SHA256 on the given passphrase
func GeneratePrivateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// GenerateEd25519 key
func GenerateEd25519Key(passphrase string) []byte {
	hash := ed25519.NewKeyFromSeed([]byte(passphrase))
	return hash[:]
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
	privateKey := GeneratePrivateKey(passphrase)
	privateKey  = GenerateEd25519Key(string(privateKey))
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate public key
	publicKey, _ := privateKey.Public().(ed25519.PublicKey)  
	fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(publicKey))

	// ssh format public key
	sshPublicKey, _ := ssh.NewPublicKey(publicKey)
	fmt.Printf("SSH Public Key (hex): %s\n", hex.EncodeToString(sshPublicKey))
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)


	// ssh format private key
	pemBlock, _ :=  marshalOpenSSHPrivateKey(privateKey, ""+time.Now().Format("2006-01-02"))

	// save key pair to files
	pri := "key_ssh"
	pub := "key_ssh.pub"

	os.WriteFile(pri, pem.EncodeToMemory(pemBlock), 0600)
	os.WriteFile(pub, publicKeyBytes, 0644)

	fmt.Println("pri:", pri)
	fmt.Println("pub:", pub)
	config := `
	Host github.com
	  HostName github.com
	  User git
	  IdentityFile ~/.ssh/key_ssh
	`
	fmt.Println("~/.ssh/config:", config)
}


func marshalOpenSSHPrivateKey(key ed25519.PrivateKey) (*pem.Block, error){
	// The block type for modern OpenSSH keys
	blockType := "OPENSSH PRIVATE KEY"

	// The OpenSSH private key format is a custom binary format.
	// We build it piece by piece.
	// See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
	
	// A random "checkint"
	var checkint uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &checkint); err != nil {
		return nil, err
	}
	
	// The binary payload
	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	w.CipherName = "none"
	w.KdfName = "none"
	w.KdfOpts = ""
	w.NumKeys = 1

	// Public key part
	pk1, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	w.PubKey = pk1.Marshal()

	// Private key part
	var pk2 struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte
	}
	pk2.Check1 = checkint
	pk2.Check2 = checkint
	pk2.Keytype = ssh.KeyAlgoED25519
	pk2.Pub = key.Public().(ed25519.PublicKey)
	pk2.Priv = key
	pk2.Comment = ""
	
	// Padding
	blockLen := len(ssh.Marshal(pk2))
	padLen := (8 - (blockLen % 8)) % 8
	pk2.Pad = make([]byte, padLen)
	for i := 0; i < padLen; i++ {
		pk2.Pad[i] = byte(i + 1)
	}
	
	w.PrivKeyBlock = ssh.Marshal(pk2)

	// Final assembly
	magic := []byte("openssh-key-v1\x00")
	magic = append(magic, ssh.Marshal(w)...)
	
	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: magic,
	}

	return pemBlock, nil
}

