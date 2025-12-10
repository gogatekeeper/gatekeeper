package models

type ScopesRepresentation struct {
	ID   *string `json:"_id"`
	Name *string `json:"name"`
}

type ResourceRepresentation struct {
	ID             *string                 `json:"_id"`
	ResourceScopes *[]ScopesRepresentation `json:"scopes"`
}

type CreatePermissionTicketParams struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type PermissionTicketRepresentation struct {
	Ticket string `json:"ticket"`
}
