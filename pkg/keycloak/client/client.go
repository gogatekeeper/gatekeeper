package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	keycloak_models "github.com/gogatekeeper/gatekeeper/pkg/keycloak/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
)

type ResponseError struct {
	ErrorMsg string `json:"error"`
	ErroDesc string `json:"error_description"`
	Status   int
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("code: %d, msg: %s, desc: %s", e.Status, e.ErrorMsg, e.ErroDesc)
}

type Client struct {
	*resty.Client

	ClientID *string
}

func New(clientID *string) *Client {
	return &Client{Client: resty.New(), ClientID: clientID}
}

func (client *Client) Login(
	ctx context.Context,
	clientSecret *string,
	username *string,
	password *string,
	grantType string,
) (*models.TokenResponse, error) {
	params := map[string]string{}
	params["client_id"] = *client.ClientID
	params["grant_type"] = grantType

	if clientSecret != nil {
		params["client_secret"] = *clientSecret
	}

	if username != nil {
		params["username"] = *username
	}

	if password != nil {
		params["password"] = *password
	}

	errorResponse := &ResponseError{}

	resp, err := client.Client.R().
		SetContext(ctx).
		SetFormData(params).
		SetError(&errorResponse).
		Post(constant.IdpTokenURI)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		errorResponse.Status = resp.StatusCode()
		return nil, errorResponse
	}

	token := &models.TokenResponse{}

	err = json.Unmarshal(resp.Body(), token)
	if err != nil {
		return nil, err
	}

	return token, err
}

func (client *Client) GetResources(
	ctx context.Context,
	token string,
	uri string,
	scope *string,
) ([]*keycloak_models.ResourceRepresentation, error) {
	errorResponse := &ResponseError{}

	resourceIDs := []string{}
	req := client.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetQueryParam("matchingURI", "true").
		SetQueryParam("uri", uri).
		SetResult(&resourceIDs).
		SetError(&errorResponse)

	if scope != nil {
		req.SetQueryParam("scope", *scope)
	}

	resp, err := req.Get(constant.IdpResourcesSetURI)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		errorResponse.Status = resp.StatusCode()
		return nil, errorResponse
	}

	resources := make([]*keycloak_models.ResourceRepresentation, 0)

	for _, resourceID := range resourceIDs {
		resource := &keycloak_models.ResourceRepresentation{}

		resp, err = client.R().
			SetContext(ctx).
			SetAuthToken(token).
			SetResult(&resource).
			SetError(&errorResponse).
			SetPathParam("id", resourceID).
			Get(constant.IdpResourceSetURI)
		if err != nil {
			return nil, err
		}

		if resp.IsError() {
			errorResponse.Status = resp.StatusCode()
			return nil, errorResponse
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (client *Client) CreatePermissionTicket(
	ctx context.Context,
	token string,
	resourceID string,
	resourceScopes []string,
) (string, error) {
	params := &keycloak_models.CreatePermissionTicketParams{}
	params.ResourceID = resourceID
	params.ResourceScopes = resourceScopes
	permissions := make([]*keycloak_models.CreatePermissionTicketParams, 0)
	permissions = append(permissions, params)

	errorResponse := &ResponseError{}
	ticket := &keycloak_models.PermissionTicketRepresentation{}

	resp, err := client.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetBody(permissions).
		SetResult(ticket).
		SetError(&errorResponse).
		SetHeader(constant.HeaderContentType, "application/json").
		Post(constant.IdpProtectPermURI)
	if err != nil {
		return "", err
	}

	if resp.IsError() {
		errorResponse.Status = resp.StatusCode()
		return "", errorResponse
	}

	return ticket.Ticket, nil
}

func (client *Client) GetRequestingPartyToken(
	ctx context.Context,
	token string,
	permToken string,
	grantType string,
) (string, error) {
	errorResponse := &ResponseError{}
	rpt := &models.TokenResponse{}

	resp, err := client.Client.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetFormData(map[string]string{
			"grant_type": grantType,
			"ticket":     permToken,
		}).
		SetError(&errorResponse).
		SetResult(rpt).
		Post(constant.IdpTokenURI)
	if err != nil {
		return "", err
	}

	if resp.IsError() {
		errorResponse.Status = resp.StatusCode()
		return "", errorResponse
	}

	return rpt.AccessToken, nil
}
