package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	mcp "github.com/metoro-io/mcp-golang"
	"github.com/metoro-io/mcp-golang/transport/stdio"
	"math/big"
	"strings"
)

// HelloArgs represents the arguments for the hello tool
type Base64Args struct {
	Action string `json:"action" jsonschema:"required,enum=encode,enum=decode,description=The action to perform (encode or decode)"`
	Input  string `json:"input" jsonschema:"required,description=The input string to process"`
}

// CalculateArgs represents the arguments for the calculate tool
type CalculateArgs struct {
	Operation string  `json:"operation" jsonschema:"required,enum=add,enum=subtract,enum=multiply,enum=divide,description=The mathematical operation to perform"`
	A         float64 `json:"a" jsonschema:"required,description=First number"`
	B         float64 `json:"b" jsonschema:"required,description=Second number"`
}

// TimeArgs represents the arguments for the current time tool
type TimeArgs struct {
	Format string `json:"format,omitempty" jsonschema:"description=Optional time format (default: RFC3339)"`
}

// PromptArgs represents the arguments for custom prompts
type PromptArgs struct {
	Input string `json:"input" jsonschema:"required,description=The input text to process"`
}

// AESDecryptArgs represents the arguments for AES decryption
type AESDecryptArgs struct {
	Ciphertext string `json:"ciphertext" jsonschema:"required,description=The ciphertext to decrypt"`
	Key        string `json:"key" jsonschema:"required,description=The decryption key"`
	Mode       string `json:"mode" jsonschema:"required,enum=ECB,enum=CBC,enum=CTR,description=The AES mode (ECB, CBC, CTR)"`
	IV         string `json:"iv,omitempty" jsonschema:"description=The initialization vector (required for CBC and CTR)"`
}

// RSAFactorArgs represents the arguments for RSA factorization
type RSAFactorArgs struct {
	N string `json:"n" jsonschema:"required,description=The large number to factorize"`
}

// XORCipherArgs represents the arguments for XOR cipher
type XORCipherArgs struct {
	Input string `json:"input" jsonschema:"required,description=The input string"`
	Key   string `json:"key" jsonschema:"required,description=The XOR key"`
}

type CaesarShiftArgs struct {
	Input string `json:"input" jsonschema:"required,description=The input string to process"`
}

// VigenereDecryptArgs represents the arguments for Vigenere decryption
type VigenereDecryptArgs struct {
	Ciphertext string `json:"ciphertext" jsonschema:"required,description=The ciphertext to decrypt"`
	Key        string `json:"key" jsonschema:"required,description=The decryption key"`
}

// FrequencyAnalysisArgs represents the arguments for frequency analysis
type FrequencyAnalysisArgs struct {
	Text string `json:"text" jsonschema:"required,description=The text to analyze"`
}

func main() {
	// Create a transport for the server
	serverTransport := stdio.NewStdioServerTransport()

	// Create a new server with the transport
	server := mcp.NewServer(serverTransport)

	// Register hello tool
	err := server.RegisterTool("base64", "Encodes or decodes base64 strings", func(args Base64Args) (*mcp.ToolResponse, error) {
		var result string
		switch args.Action {
		case "encode":
			result = base64.StdEncoding.EncodeToString([]byte(args.Input))
		case "decode":
			decoded, err := base64.StdEncoding.DecodeString(args.Input)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 input: %v", err)
			}
			result = string(decoded)
		default:
			return nil, fmt.Errorf("unknown action: %s", args.Action)
		}
		return mcp.NewToolResponse(mcp.NewTextContent(result)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register calculate tool
	err = server.RegisterTool("calculate", "Performs basic mathematical operations", func(args CalculateArgs) (*mcp.ToolResponse, error) {
		var result float64
		switch args.Operation {
		case "add":
			result = args.A + args.B
		case "subtract":
			result = args.A - args.B
		case "multiply":
			result = args.A * args.B
		case "divide":
			if args.B == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			result = args.A / args.B
		default:
			return nil, fmt.Errorf("unknown operation: %s", args.Operation)
		}
		message := fmt.Sprintf("Result of %s: %.2f", args.Operation, result)
		return mcp.NewToolResponse(mcp.NewTextContent(message)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register current time tool

	// Start the server
	if err := server.Serve(); err != nil {
		panic(err)
	}
	err = server.RegisterTool("aes_decrypt", "Decrypts AES encrypted data in various modes", func(args AESDecryptArgs) (*mcp.ToolResponse, error) {
		// Decode ciphertext
		ciphertext, err := base64.StdEncoding.DecodeString(args.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("invalid ciphertext: %v", err)
		}

		// Validate key length
		key := []byte(args.Key)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("invalid key length: must be 16, 24, or 32 bytes")
		}

		// Create cipher block
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher block: %v", err)
		}

		// Decrypt based on mode
		var plaintext []byte
		switch args.Mode {
		case "ECB":
			if len(ciphertext)%aes.BlockSize != 0 {
				return nil, fmt.Errorf("ciphertext length must be a multiple of block size")
			}
			plaintext = make([]byte, len(ciphertext))
			for bs, be := 0, aes.BlockSize; bs < len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
				block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
			}

		case "CBC":
			if args.IV == "" {
				return nil, fmt.Errorf("IV is required for CBC mode")
			}
			iv, err := base64.StdEncoding.DecodeString(args.IV)
			if err != nil {
				return nil, fmt.Errorf("invalid IV: %v", err)
			}
			if len(iv) != aes.BlockSize {
				return nil, fmt.Errorf("invalid IV length: must be %d bytes", aes.BlockSize)
			}
			mode := cipher.NewCBCDecrypter(block, iv)
			plaintext = make([]byte, len(ciphertext))
			mode.CryptBlocks(plaintext, ciphertext)

		case "CTR":
			if args.IV == "" {
				return nil, fmt.Errorf("IV is required for CTR mode")
			}
			iv, err := base64.StdEncoding.DecodeString(args.IV)
			if err != nil {
				return nil, fmt.Errorf("invalid IV: %v", err)
			}
			stream := cipher.NewCTR(block, iv)
			plaintext = make([]byte, len(ciphertext))
			stream.XORKeyStream(plaintext, ciphertext)

		default:
			return nil, fmt.Errorf("unsupported mode: %s", args.Mode)
		}

		// Remove padding (PKCS7)
		if args.Mode == "ECB" || args.Mode == "CBC" {
			padding := int(plaintext[len(plaintext)-1])
			if padding > aes.BlockSize || padding == 0 {
				return nil, fmt.Errorf("invalid padding")
			}
			plaintext = plaintext[:len(plaintext)-padding]
		}

		return mcp.NewToolResponse(mcp.NewTextContent(string(plaintext))), nil
	})
	if err != nil {
		panic(err)
	}

	// Register RSA factorization tool
	err = server.RegisterTool("rsa_factor_n", "Attempts to factorize a large number", func(args RSAFactorArgs) (*mcp.ToolResponse, error) {
		n := new(big.Int)
		n, ok := n.SetString(args.N, 10)
		if !ok {
			return nil, fmt.Errorf("invalid number")
		}
		// Simple trial division (for demonstration purposes)
		// In real-world use, implement a proper factorization algorithm
		for i := big.NewInt(2); i.Cmp(n) < 0; i.Add(i, big.NewInt(1)) {
			if new(big.Int).Mod(n, i).Cmp(big.NewInt(0)) == 0 {
				return mcp.NewToolResponse(mcp.NewTextContent(fmt.Sprintf("Factor found: %s", i.String()))), nil
			}
		}
		return mcp.NewToolResponse(mcp.NewTextContent("No factors found")), nil
	})
	if err != nil {
		panic(err)
	}

	// Register XOR cipher tool
	err = server.RegisterTool("xor_cipher", "Performs XOR encryption/decryption", func(args XORCipherArgs) (*mcp.ToolResponse, error) {
		key := []byte(args.Key)
		input := []byte(args.Input)
		result := make([]byte, len(input))
		for i := 0; i < len(input); i++ {
			result[i] = input[i] ^ key[i%len(key)]
		}
		return mcp.NewToolResponse(mcp.NewTextContent(string(result))), nil
	})
	if err != nil {
		panic(err)
	}
	err = server.RegisterTool("caesarShift", "Performs all possible Caesar cipher shifts (0-25)", func(args CaesarShiftArgs) (*mcp.ToolResponse, error) {
		results := make([]string, 26)
		for shift := 0; shift < 26; shift++ {
			var shiftedText strings.Builder
			for _, char := range args.Input {
				if char >= 'a' && char <= 'z' {
					shiftedChar := 'a' + (char-'a'+rune(shift))%26
					shiftedText.WriteRune(shiftedChar)
				} else if char >= 'A' && char <= 'Z' {
					shiftedChar := 'A' + (char-'A'+rune(shift))%26
					shiftedText.WriteRune(shiftedChar)
				} else {
					shiftedText.WriteRune(char)
				}
			}
			results[shift] = fmt.Sprintf("Shift %2d: %s", shift, shiftedText.String())
		}
		return mcp.NewToolResponse(mcp.NewTextContent(strings.Join(results, "\n"))), nil
	})
	if err != nil {
		panic(err)
	}

	// Register Vigenère decryption tool
	err = server.RegisterTool("vigenere_decrypt", "Decrypts Vigenère cipher", func(args VigenereDecryptArgs) (*mcp.ToolResponse, error) {
		key := []rune(args.Key)
		keyIndex := 0
		result := make([]rune, len(args.Ciphertext))
		for i, char := range args.Ciphertext {
			if char >= 'a' && char <= 'z' {
				shift := key[keyIndex%len(key)] - 'a'
				result[i] = 'a' + (char-'a'-shift+26)%26
				keyIndex++
			} else if char >= 'A' && char <= 'Z' {
				shift := key[keyIndex%len(key)] - 'A'
				result[i] = 'A' + (char-'A'-shift+26)%26
				keyIndex++
			} else {
				result[i] = char
			}
		}
		return mcp.NewToolResponse(mcp.NewTextContent(string(result))), nil
	})
	if err != nil {
		panic(err)
	}

	// Register frequency analysis tool
	err = server.RegisterTool("frequency_analysis", "Performs frequency analysis on text", func(args FrequencyAnalysisArgs) (*mcp.ToolResponse, error) {
		freq := make(map[rune]int)
		total := 0
		for _, char := range args.Text {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
				freq[char]++
				total++
			}
		}
		result := "Character frequencies:\n"
		for char, count := range freq {
			result += fmt.Sprintf("%c: %.2f%%\n", char, float64(count)/float64(total)*100)
		}
		return mcp.NewToolResponse(mcp.NewTextContent(result)), nil
	})
	if err != nil {
		panic(err)
	}
	// Keep the server running
	select {}
}
