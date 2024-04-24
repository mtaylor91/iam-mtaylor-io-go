package iam

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type Session struct {
	// The session id
	Id string `json:"id"`
	// The user id
	User string `json:"user"`
	// The IP address
	Address string `json:"address"`
	// The expiry time
	Expiration string `json:"expiration"`
}

type LocalSession struct {
	// Inherited fields
	Session
	// The session token
	Token string `json:"token"`
}

// Login logs in the user
func (c *Client) Login(userId, secretKeyBase64 string) (*LocalSession, error) {
	var secretKey ed25519.PrivateKey
	var err error

	// Decode the secret key
	secretKeyBytes, err := base64.StdEncoding.DecodeString(secretKeyBase64)
	if err != nil {
		return nil, err
	}
	secretKey = ed25519.PrivateKey(secretKeyBytes)

	// Create the user identity
	c.userIdentity = &UserIdentity{
		userId:    userId,
		publicKey: secretKey.Public().(ed25519.PublicKey),
		secretKey: secretKey,
	}

	// Create the request
	req, err := http.NewRequest("POST", c.buildURL("/user/sessions", ""), nil)
	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	// Check the status code
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Decode the response
	var localSession LocalSession
	err = json.NewDecoder(resp.Body).Decode(&localSession)
	if err != nil {
		return nil, err
	}

	// Set the local session
	c.localSession = &localSession

	// Return the local session
	return &localSession, nil
}

// Logout logs out the user
func (c *Client) Logout() error {

	// Create the request
	sessionURL := c.buildURL("/user/sessions/"+c.localSession.Id, "")
	req, err := http.NewRequest("DELETE", sessionURL, nil)
	if err != nil {
		return err
	}

	// Execute the request
	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Clear the local session
	c.localSession = nil
	c.userIdentity = nil

	// Return success
	return nil
}

// Refresh refreshes the session
func (c *Client) Refresh(
	userId, secretKeyBase64, sessionId, sessionToken string,
) (*LocalSession, error) {
	var secretKey ed25519.PrivateKey
	var err error

	// Decode the secret key
	secretKeyBytes, err := base64.StdEncoding.DecodeString(secretKeyBase64)
	if err != nil {
		return nil, err
	}
	secretKey = ed25519.PrivateKey(secretKeyBytes)

	// Create the user identity
	c.userIdentity = &UserIdentity{
		userId:    userId,
		publicKey: secretKey.Public().(ed25519.PublicKey),
		secretKey: secretKey,
	}

	// Create the request
	refreshUrl := c.buildURL("/user/sessions/"+sessionId+"/refresh", "")
	req, err := http.NewRequest("POST", refreshUrl, nil)
	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Decode the response
	var localSession LocalSession
	err = json.NewDecoder(resp.Body).Decode(&localSession)
	if err != nil {
		return nil, err
	}

	// Set the local session
	localSession.Token = sessionToken
	c.localSession = &localSession

	// Return success
	return &localSession, nil
}
