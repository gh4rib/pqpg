package main

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
)

// ---------------------------------------------------------------------
// Core UI Helpers
// ---------------------------------------------------------------------

func readInput(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// selectContact gracefully handles the Address Book UX, allowing fallback to manual path entry.
func selectContact(reader *bufio.Reader, sessionStore *identity.SessionStore, role string) (*identity.Profile, error) {
	contacts, err := sessionStore.ListContacts()
	if err != nil || len(contacts) == 0 {
		fmt.Println("[-] Address book is empty.")
		fmt.Printf("Enter path to %s'S public folder manually (e.g., ./keys_bob/public): ", role)
		pubPath := readInput(reader)
		return identity.LoadProfile(pubPath)
	}

	fmt.Println("\n--- ADDRESS BOOK ---")
	for i, c := range contacts {
		fmt.Printf(" %d) %s <%s>\n", i+1, c.Name, c.Email)
	}
	fmt.Println(" 0) Enter path manually")
	fmt.Printf("Select %s [0-%d]: ", role, len(contacts))

	choiceStr := readInput(reader)
	choice, err := strconv.Atoi(choiceStr)
	if err != nil || choice < 0 || choice > len(contacts) {
		return nil, errors.New("invalid selection")
	}

	if choice == 0 {
		fmt.Printf("Enter path to %s'S public folder manually: ", role)
		pubPath := readInput(reader)
		return identity.LoadProfile(pubPath)
	}

	return &contacts[choice-1], nil
}
