package iam

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

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

// Do sends an HTTP request
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var err error

	// Sign the request
	err = c.signRequest(req)
	if err != nil {
		return nil, err
	}

	// Execute the request
	return c.HTTP.Do(req)
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
	req.Header.Add("X-MTaylor-IO-Public-Key",
		base64.StdEncoding.EncodeToString(c.userIdentity.publicKey))
	if c.localSession != nil {
		req.Header.Add("X-MTaylor-IO-Session-Token", c.localSession.Token)
	}

	// Return success
	return nil
}
