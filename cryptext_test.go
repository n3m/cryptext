package cryptext

import "testing"

func TestProcessAsAWhole(t *testing.T) {
	phrase := "ThisShouldBeAValidPhrase"
	test_data := "A rabbit crosses the road 99 times"

	encrypted, err := EncryptWithPhrase(phrase, test_data)
	if err != nil {
		t.Fatalf("Encryption Error: %s", err)
	}

	decrypted, err := DecryptWithPhrase(phrase, []byte(encrypted))
	if err != nil {
		t.Fatalf("Decryption Error: %s", err)
	}

	if decrypted != test_data {
		t.Fatalf("Expected: %s, got: %s", test_data, decrypted)
	}
}
