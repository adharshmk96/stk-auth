package services_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/infra/config"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/stretchr/testify/assert"
)

const (
	TEST_KEY_DIR          = "./test_keys"
	TEST_PRIVATE_KEY_PATH = TEST_KEY_DIR + "/private_key.pem"
	TEST_PUBLIC_KEY_PATH  = TEST_KEY_DIR + "/public_key.pem"
)

func generateTestKeys() error {
	privateKeyPEM, publicKeyPEM, err := mocks.GenerateKeyPair()
	if err != nil {
		return err
	}

	os.Mkdir(TEST_KEY_DIR, 0700)

	err = ioutil.WriteFile(TEST_PRIVATE_KEY_PATH, privateKeyPEM, 0600)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(TEST_PUBLIC_KEY_PATH, publicKeyPEM, 0600)
	if err != nil {
		return err
	}

	return nil
}

func removeTestKeys() {
	os.Remove(TEST_PRIVATE_KEY_PATH)
	os.Remove(TEST_PUBLIC_KEY_PATH)
	os.Remove(TEST_KEY_DIR)
}

func TestReadFunctions(t *testing.T) {
	err := generateTestKeys()
	if err != nil {
		t.Fatalf(fmt.Sprintf("Error generating test keys: %s", err))
	}

	t.Run("test read private key from environment variable", func(t *testing.T) {

		os.Setenv(config.ENV_JWT_EDCA_PRIVATE_KEY, "test-private-key")
		key := services.ReadPrivateKey()
		assert.Equal(t, "test-private-key", string(key))
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
	})

	t.Run("test read private key from file", func(t *testing.T) {
		os.Setenv(config.ENV_JWT_EDCA_PRIVATE_KEY_PATH, TEST_PRIVATE_KEY_PATH)
		key := services.ReadPrivateKey()
		assert.NotNil(t, key)
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY_PATH")
	})

	t.Run("test read public key from environment variable", func(t *testing.T) {
		os.Setenv(config.ENV_JWT_EDCA_PUBLIC_KEY, "test-public-key")
		key := services.ReadPublicKey()
		assert.Equal(t, "test-public-key", string(key))
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
	})

	t.Run("test read public key from file", func(t *testing.T) {
		os.Setenv(config.ENV_JWT_EDCA_PUBLIC_KEY_PATH, TEST_PUBLIC_KEY_PATH)
		key := services.ReadPublicKey()
		assert.NotNil(t, key)
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY_PATH")
	})

	removeTestKeys()
}

func TestErrorOnInvalidKeys(t *testing.T) {
	err := generateTestKeys()
	if err != nil {
		t.Fatalf(fmt.Sprintf("Error generating test keys: %s", err))
	}

	t.Run("test error on invalid private key", func(t *testing.T) {
		os.Setenv(config.ENV_JWT_EDCA_PRIVATE_KEY, "invalid-private-key")
		_, err := services.GetJWTPrivateKey()
		assert.NotNil(t, err, "Expected error when trying to parse an invalid private key, but got nil")
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
	})

	t.Run("test error on invalid public key", func(t *testing.T) {
		os.Setenv(config.ENV_JWT_EDCA_PUBLIC_KEY, "invalid-public-key")
		_, err := services.GetJWTPublicKey()
		assert.NotNil(t, err, "Expected error when trying to parse an invalid public key, but got nil")
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
	})

	removeTestKeys()
}
