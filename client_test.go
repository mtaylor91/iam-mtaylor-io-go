package iam

import (
	"os"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	iamURL, ok := os.LookupEnv("MTAYLOR_IO_URL")
	if !ok {
		iamURL = "https://iam.mtaylor.io"
	}

	client, err := NewClient(iamURL)
	if err != nil {
		t.Fatal(err)
	}

	userEmail, ok := os.LookupEnv("MTAYLOR_IO_EMAIL")
	if !ok {
		t.Fatal("MTAYLOR_IO_EMAIL not set")
	}

	userSecretKey, ok := os.LookupEnv("MTAYLOR_IO_SECRET_KEY")
	if !ok {
		t.Fatal("MTAYLOR_IO_SECRET_KEY not set")
	}

	session, err := client.Login(userEmail, userSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Refresh(
		userEmail, userSecretKey, session.Id, session.Token)
	if err != nil {
		t.Fatal(err)
	}

	authResp, err := client.Authorize(&AuthorizationRequest{
		User:     userEmail,
		Action:   "Write",
		Resource: "/users",
		Host:     client.host,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, authResp.Effect, "Allow")

	authResp, err = client.Authorize(&AuthorizationRequest{
		User:     userEmail,
		Action:   "Read",
		Resource: "/users",
		Host:     "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, authResp.Effect, "Deny")

	err = client.Logout()
	if err != nil {
		t.Fatal(err)
	}
}
