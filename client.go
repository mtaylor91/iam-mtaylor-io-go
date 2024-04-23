package iam

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type AuthorizationRequest struct {
	// The user
	User string `json:"user"`
	// The action
	Action string `json:"action"`
	// The resource
	Resource string `json:"resource"`
	// The host
	Host string `json:"host"`
}

type AuthorizationResponse struct {
	// The authorization effect
	Effect string `json:"effect"`
}

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

type UserIdentity struct {
	// The user id
	userId string
	// The public key
	publicKey ed25519.PublicKey
	// The secret key
	secretKey ed25519.PrivateKey
}

type Client struct {
	// The http client
	HTTP *http.Client
	// The protocol for the client
	protocol string
	// The host for the client
	host string
	// The port for the client
	port string
	// The local session for the client
	localSession *LocalSession
	// The user identity for the client
	userIdentity *UserIdentity
}

// NewClient creates a new client
func NewClient(iamURL string) (*Client, error) {

	// Parse the URL
	u, err := url.Parse(iamURL)
	if err != nil {
		return nil, err
	}

	// Return the client
	return &Client{
		HTTP:         http.DefaultClient,
		protocol:     u.Scheme,
		host:         u.Hostname(),
		port:         u.Port(),
		localSession: nil,
		userIdentity: nil,
	}, nil
}

// buildURL builds a URL
func (c *Client) buildURL(path, rawQuery string) string {
	var hostString string

	if c.protocol == "http" && c.port == "80" {
		hostString = c.host
	} else if c.protocol == "https" && c.port == "443" {
		hostString = c.host
	} else if c.port != "" {
		hostString = c.host + ":" + c.port
	} else {
		hostString = c.host
	}

	u := url.URL{
		Scheme:   c.protocol,
		Host:     hostString,
		Path:     path,
		RawQuery: rawQuery,
	}

	return u.String()
}

// publicKeyBase64 returns the base64 encoded public key
func (c *Client) publicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(c.userIdentity.publicKey)
}

// signRequest signs the request
func (c *Client) signRequest(req *http.Request) error {

	// Generate a request id
	requestId, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	// Construct the message
	messageParts := []string{
		// The method
		req.Method,
		// The hostname
		req.URL.Hostname(),
		// The path
		req.URL.Path,
		// The query
		req.URL.RawQuery,
		// The request id
		requestId.String(),
	}
	if c.localSession != nil {
		messageParts = append(messageParts, c.localSession.Token)
	}
	message := []byte(strings.Join(messageParts, "\n"))

	// Sign the message
	signature, err := c.userIdentity.secretKey.Sign(nil, message, &ed25519.Options{})
	if err != nil {
		return err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Add the headers
	req.Header.Add("Authorization", "Signature "+signatureBase64)
	req.Header.Add("X-MTaylor-IO-User-Id", c.userIdentity.userId)
	req.Header.Add("X-MTaylor-IO-Request-Id", requestId.String())
	req.Header.Add("X-MTaylor-IO-Public-Key", c.publicKeyBase64())
	if c.localSession != nil {
		req.Header.Add("X-MTaylor-IO-Session-Token", c.localSession.Token)
	}

	// Return success
	return nil
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

	// Sign the request
	err = c.signRequest(req)
	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := c.HTTP.Do(req)
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

	// Sign the request
	err = c.signRequest(req)
	if err != nil {
		return err
	}

	// Execute the request
	resp, err := c.HTTP.Do(req)
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

	// Sign the request
	err = c.signRequest(req)
	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := c.HTTP.Do(req)
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

// Authorize requests authorization for the specified user to perform the
// specified action on the specified resource at the specified host
func (c *Client) Authorize(
	userId, action, resource, host string,
) (*AuthorizationResponse, error) {

	// Create the request
	authorizeUrl := c.buildURL("/authorize", "")
	authorizationRequest := &AuthorizationRequest{
		User:     userId,
		Action:   action,
		Resource: resource,
		Host:     host,
	}
	authorizationRequestBytes, err := json.Marshal(authorizationRequest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", authorizeUrl,
		bytes.NewReader(authorizationRequestBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	err = c.signRequest(req)
	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Decode the response
	var authorizationResponse AuthorizationResponse
	err = json.NewDecoder(resp.Body).Decode(&authorizationResponse)
	if err != nil {
		return nil, err
	}

	// Return the authorization response
	return &authorizationResponse, nil
}
