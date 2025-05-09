//
// This example demonstrates how to create a simple CLI tool using Cobra
// that reads a master key from an environment variable. It uses the
// LocalStore backend to store and retrieve secrets from a local JSON file.
//
// Usage examples (assuming the CLI is named "vault"):
//   vault store myKey "Hello World!"
//   vault get myKey
//   vault list
//
// Requirements:
//   - Set the environment variable MASTER_KEY to a 64-character hex string
//     representing 32 bytes (for AES-256).
//   - Provide a JSON file path (e.g., /tmp/vault-secrets.json) via a flag
//     or default in the code below. If it doesn’t exist, use --create to
//     initialize it.

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	securestorage "github.com/Cray-HPE/hms-securestorage"
	"github.com/spf13/cobra"
)

var (
	filename string
	create   bool
	rootCmd  = &cobra.Command{
		Use:   "vault",
		Short: "A simple CLI for secure local storage using LocalStore",
		Long:  "vault is a basic demonstration of using the LocalStore backend to store, retrieve, list secrets, and generate a master key using Cobra.",
	}
	storeCmd = &cobra.Command{
		Use:   "store [key] [value]",
		Short: "Store a secret value for the given key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]
			ls, err := getLocalStore()
			if err != nil {
				return fmt.Errorf("could not initialize local store: %v", err)
			}
			// Store the secret
			err = ls.Store(key, map[string]interface{}{"value": value})
			if err != nil {
				return fmt.Errorf("failed to store secret: %v", err)
			}
			fmt.Printf("Stored secret for key '%s'.\n", key)
			return nil
		},
	}
	getCmd = &cobra.Command{
		Use:   "get [key]",
		Short: "Retrieve a stored secret by key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			ls, err := getLocalStore()
			if err != nil {
				return fmt.Errorf("could not initialize local store: %v", err)
			}
			// Lookup the secret
			var output map[string]interface{}
			err = ls.Lookup(key, &output)
			if err != nil {
				return fmt.Errorf("failed to retrieve secret: %v", err)
			}
			fmt.Printf("Secret for key '%s': %v\n", key, output["value"])
			return nil
		},
	}
	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all stored secret keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			ls, err := getLocalStore()
			if err != nil {
				return fmt.Errorf("could not initialize local store: %v", err)
			}
			keys, err := ls.LookupKeys("")
			if err != nil {
				return fmt.Errorf("failed to list keys: %v", err)
			}
			if len(keys) == 0 {
				fmt.Println("No secrets found.")
				return nil
			}
			fmt.Println("Stored keys:")
			for _, k := range keys {
				fmt.Printf("- %s\n", k)
			}
			return nil
		},
	}
	// Generates a new 32-byte (hex-encoded) master key.
	genMasterKeyCmd = &cobra.Command{
		Use:   "genmasterkey",
		Short: "Generate a new 32-byte master key in hex",
		Long:  "Generates a new 32-byte random key for AES-256, displayed in hex. You can set MASTER_KEY to this value for local store usage.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mk, err := securestorage.GenerateMasterKey()
			if err != nil {
				return fmt.Errorf("failed to generate master key: %v", err)
			}
			fmt.Println("New MASTER_KEY (hex):", mk)
			return nil
		},
	}
)

// getLocalStore creates a new LocalStore using the MASTER_KEY environment variable.
func getLocalStore() (*securestorage.LocalStore, error) {
	masterKeyHex := os.Getenv("MASTER_KEY")
	if masterKeyHex == "" {
		return nil, fmt.Errorf("environment variable MASTER_KEY not set or empty")
	}
	_, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MASTER_KEY: %v", err)
	}

	ls, err := securestorage.NewLocalSecretStore(masterKeyHex, filename, create)
	if err != nil {
		return nil, err
	}
	return ls, nil
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(storeCmd, getCmd, listCmd, genMasterKeyCmd)

	// Add file-related flags
	rootCmd.PersistentFlags().StringVarP(&filename, "file", "f", "/tmp/vault-secrets.json", "Path to the JSON file for storing secrets")
	rootCmd.PersistentFlags().BoolVarP(&create, "create", "c", false, "Create the JSON file if it doesn't exist")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
