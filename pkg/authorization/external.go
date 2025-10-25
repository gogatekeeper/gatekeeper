package authorization

type AuthzDecision int

const (
	UndefinedAuthz AuthzDecision = iota
	AllowedAuthz   AuthzDecision = iota
	DeniedAuthz    AuthzDecision = iota
)

const (
	DeniedAuthzString    string = "Denied"
	AllowedAuthzString   string = "Allowed"
	UndefinedAuthzString string = "Undefined"
)

func (decision AuthzDecision) String() string {
	switch decision {
	case AllowedAuthz:
		return AllowedAuthzString
	case DeniedAuthz:
		return DeniedAuthzString
	case UndefinedAuthz:
		return UndefinedAuthzString
	}

	return DeniedAuthzString
}

type Provider interface {
	Authorize() (AuthzDecision, error)
}
