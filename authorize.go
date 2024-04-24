package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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

// Authorize requests authorization for the specified user to perform the
// specified action on the specified resource at the specified host
func (c *Client) Authorize(
	authorizationRequest *AuthorizationRequest,
) (*AuthorizationResponse, error) {

	// Create the request
	authorizeUrl := c.buildURL("/authorize", "")
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
	var authorizationResponse AuthorizationResponse
	err = json.NewDecoder(resp.Body).Decode(&authorizationResponse)
	if err != nil {
		return nil, err
	}

	// Return the authorization response
	return &authorizationResponse, nil
}
