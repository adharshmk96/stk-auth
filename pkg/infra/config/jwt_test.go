package config_test

import (
	"os"
	"testing"

	"github.com/adharshmk96/auth-server/pkg/infra/config"
	"github.com/stretchr/testify/assert"
)

var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8p0Wv/07CoOip
XxtZHmHCyz+hV1gJqnOhyhmc68XQynXDI96O65PKUCjYxtncAg3KSZExYvX6obyv
FsnluNmHffy+QBVQReGHZ2yTzqpionwuJ4ZYLNMGbiDk2td9x8DGdSX2fFZF1qnJ
0ulSph44anzF0Uqx6B5fi9M6IkD622/6GfMGEmE/1ssObECm66DOLzLIYOB5EHj9
RkUTaoCs88Q9/uFejKk1Y0QOObnPx+MKJ9I36vplxl2fKRfHATvpqSt/UYsElDu5
zKEi1Olewe8ozv4C/8cmIlJ6b2N3M89izRo0ZUCY/TGp46O5gAsNK+IQnHSk7kDb
Del3WsSpAgMBAAECggEAY3mcUGJCKHRqWizRIdvYVruPcMa6oFYlpNEJUmosI50u
HViDmT707f/4md24sL7QgLLsAWuaIq836+cLTLt80GoJZFQsKOjANALACOw3gc0F
x9yFhWcVWtWlOKeAa01yA/Nvshn779VyL/6rky4Oz1avNivWxBqOMXlsRsIbG2rC
mCRJFH99sO0KYAt5BgSQkI/ygunniwRH+VOhn+qzDDFhBQXjfTAW0CbRJPrXLeCs
WR0Mjo48IL++vlNGLqHhKNd85HtEv5G5QTP/I9DVCCOReoYvpsNscf332kCAkbv5
xtxKd+voKRFrTHMivJ5+Q1GVb34zcz7xJ9cVHwVNgQKBgQD4G1GMxfV9aryvtsRL
oybQG8kn03ok/lC0R7qyydDcTi8qCR7ITz0Q7iwy/cY+vE17lkmQNZr4zuLEbWJl
rhWWji8ZttcKilYcxGoycuAygTPjeaFL7joxfI2RPrPgmZUnG58KK/YbkYA8TYbO
Tn2eb0VTfV5kKVt8Z5gVcacZ2QKBgQDCp73sO+po/TJDIWLF1izhEzub44a+K1BZ
9GP/fEqCcS5lKXPt3Ob6dI4b6ybUF+MUBG7whBiAAgZ1AW5bvCgLmRAEjXUXoArd
rejmmG2bgBVCnULK3m0BSJO2IIUjLntkJ6LNvJpCRsNtsrjzjkcJ3IlsvBBA4E4Z
ZLG64OrvUQKBgDE9wsast1dH6uD45iaY3+gny5mi6DgVXVEad1xqn5BJ2CSAoOJi
j50fmBgas9DZsIsZvcnoSbSd4vXXO9MwZMp3t7NjzXQjFoopFWaj1AlSCUlZZ4DZ
bCVMMhCkoDCwaqDTY5IyPWslSo0tWdbyTw41yU2TsTsx1h1vtghzgRWpAoGATi+6
Za0bVth82+IJHpYMqMtk4hTeBny3Zap4kCKIeySjEhc4bY6RaIBwpF4r1n1RxLST
KyCkBqbJmS3d+hL1stLkUC/RnI+4TZqRNi57uD4WTA+GyJ3XAvD4A+vEDoGZJn2V
MzZSb9SkoudqysmXVyqyOG7ByI1QUXrUuM+nDkECgYByMK0F7VTpCyrXtKV9v+h8
9qMAUsn6zdHr18CFYzxr8ah8aJkA8bhWRHqOFnaDorcuJ/AeJV9irQ4cj9dhStAO
h3t4BI3tAhV779CvXoTbjwXtWGeAUOCuvTjQgJeZiuGQXaj+rQlgWCzk9HK4sV3G
QR7Naff0gsNlqCJibCwOhA==
-----END PRIVATE KEY-----
`
var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvKdFr/9OwqDoqV8bWR5h
wss/oVdYCapzocoZnOvF0Mp1wyPejuuTylAo2MbZ3AINykmRMWL1+qG8rxbJ5bjZ
h338vkAVUEXhh2dsk86qYqJ8LieGWCzTBm4g5NrXfcfAxnUl9nxWRdapydLpUqYe
OGp8xdFKsegeX4vTOiJA+ttv+hnzBhJhP9bLDmxApuugzi8yyGDgeRB4/UZFE2qA
rPPEPf7hXoypNWNEDjm5z8fjCifSN+r6ZcZdnykXxwE76akrf1GLBJQ7ucyhItTp
XsHvKM7+Av/HJiJSem9jdzPPYs0aNGVAmP0xqeOjuYALDSviEJx0pO5A2w3pd1rE
qQIDAQAB
-----END PUBLIC KEY-----
`

func setupKeys() {
	os.MkdirAll(".keys", 0666)
	os.WriteFile(".keys/private_key.pem", []byte(privateKey), 0666)
	os.WriteFile(".keys/public_key.pem", []byte(publicKey), 0666)

}

func tearDown() {
	os.RemoveAll(".keys")
}

func TestParsingKeys(t *testing.T) {

	setupKeys()

	t.Run("gets private key from dir", func(t *testing.T) {
		key, err := config.GetJWTPrivateKey()
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("gets public key from dir", func(t *testing.T) {
		key, err := config.GetJWTPublicKey()
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	tearDown()

	t.Run("fails if private key is not found", func(t *testing.T) {
		key, err := config.GetJWTPrivateKey()
		assert.Error(t, err)
		assert.Nil(t, key)
	})
	t.Run("fails if public key is not found", func(t *testing.T) {
		key, err := config.GetJWTPublicKey()
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestReadKeys(t *testing.T) {
	t.Run("reads from environment if env is set", func(t *testing.T) {
		os.Setenv("JWT_EDCA_PRIVATE_KEY", "privateKey")
		os.Setenv("JWT_EDCA_PUBLIC_KEY", "publicKey")
		key := config.ReadPrivateKey()
		assert.Equal(t, "privateKey", string(key))
		key = config.ReadPublicKey()
		assert.Equal(t, "publicKey", string(key))
		os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
		os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
	})

	t.Run("reads from file if env is not set", func(t *testing.T) {
		setupKeys()
		key := config.ReadPrivateKey()
		assert.Equal(t, privateKey, string(key))
		key = config.ReadPublicKey()
		assert.Equal(t, publicKey, string(key))
		tearDown()
	})
}
