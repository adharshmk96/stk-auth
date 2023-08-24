package helpers_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk-auth/testHelpers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	TestKeyDir         = "./test_keys"
	TestPrivateKeyPath = TestKeyDir + "/private_key.pem"
	TestPublicKeyPath  = TestKeyDir + "/public_key.pem"
)

func generateTestKeys() error {
	privateKeyPEM, publicKeyPEM, err := testHelpers.GenerateKeyPair()
	if err != nil {
		return err
	}

	os.Mkdir(TestKeyDir, 0700)

	err = os.WriteFile(TestPrivateKeyPath, privateKeyPEM, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(TestPublicKeyPath, publicKeyPEM, 0600)
	if err != nil {
		return err
	}

	return nil
}

func removeTestKeys() {
	os.Remove(TestPrivateKeyPath)
	os.Remove(TestPublicKeyPath)
	os.Remove(TestKeyDir)
}

func TestReadFunctions(t *testing.T) {
	err := generateTestKeys()
	if err != nil {
		t.Fatalf(fmt.Sprintf("Error generating test keys: %s", err))
	}

	t.Run("test read private key from environment variable", func(t *testing.T) {

		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "test-private-key")
		viper.AutomaticEnv()
		key := helpers.ReadPrivateKey()
		assert.Equal(t, "test-private-key", string(key))
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
	})

	t.Run("test read private key from file", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY_PATH, TestPrivateKeyPath)
		viper.AutomaticEnv()
		key := helpers.ReadPrivateKey()
		assert.NotNil(t, key)
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY_PATH")
	})

	t.Run("test read public key from environment variable", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY, "test-public-key")
		viper.AutomaticEnv()
		key := helpers.ReadPublicKey()
		assert.Equal(t, "test-public-key", string(key))
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
	})

	t.Run("test read public key from file", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY_PATH, TestPublicKeyPath)
		viper.AutomaticEnv()
		key := helpers.ReadPublicKey()
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
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "invalid-private-key")
		viper.AutomaticEnv()
		_, err := helpers.GetJWTPrivateKey()
		assert.NotNil(t, err, "Expected error when trying to parse an invalid private key, but got nil")
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
	})

	t.Run("test error on invalid public key", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY, "invalid-public-key")
		viper.AutomaticEnv()
		_, err := helpers.GetJWTPublicKey()
		assert.NotNil(t, err, "Expected error when trying to parse an invalid public key, but got nil")
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
	})

	removeTestKeys()
}
