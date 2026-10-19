package auth

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	SSOProvider string    `json:"sso_provider,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type Membership struct {
	Org       Org       `json:"org"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type UserSession struct {
	User        User         `json:"user"`
	Orgs        []Org        `json:"orgs"`
	Token       string       `json:"token"`
	Memberships []Membership `json:"memberships"`
}
