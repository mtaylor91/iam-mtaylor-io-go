package iam

import (
	"os"
	"testing"
)

func TestSession(t *testing.T) {
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

	err = client.Logout()
	if err != nil {
		t.Fatal(err)
	}
}
