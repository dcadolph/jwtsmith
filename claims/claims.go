package claims

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// ToMapClaims attempts to convert the provided value to jwt.MapClaims.
// If the value is already of type jwt.MapClaims, it returns the value as-is.
// If the value can be marshaled into a jwt.MapClaims, it does so and returns it.
// Otherwise, it returns an error.
func ToMapClaims(input any) (jwt.MapClaims, error) {

	if claims, ok := input.(jwt.MapClaims); ok {
		if claims == nil {
			return nil, fmt.Errorf("%w: token claims nil", ErrInvalidValue)
		}
		return claims, nil
	}

	claimsJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding claims: %w", ErrEncode, err)
	}

	var mapClaims jwt.MapClaims
	if err := json.Unmarshal(claimsJSON, &mapClaims); err != nil {
		return nil, fmt.Errorf("%w: decoding claims to jwt.MapClaims: %w", ErrDecode, err)
	}

	return mapClaims, nil
}

// DeepCopy returns a deep copy of the claims.
func DeepCopy(src jwt.MapClaims) jwt.MapClaims {
	dst := jwt.MapClaims{}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// RegisteredClaims returns the registered claims defined by the JWT spec.
//
// For more, see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
func RegisteredClaims() map[string]struct{} {
	return map[string]struct{}{
		MapKeyExpiresAt: {},
		MapKeyIssuedAt:  {},
		MapKeyNotBefore: {},
		MapKeyID:        {},
		MapKeyIssuer:    {},
		MapKeyAudience:  {},
		MapKeySubject:   {},
	}
}

// IsRegisteredClaim reports true if the claim is a standard claim.
func IsRegisteredClaim(c string) bool {
	return c == MapKeyExpiresAt ||
		c == MapKeyIssuedAt ||
		c == MapKeyNotBefore ||
		c == MapKeyID ||
		c == MapKeyIssuer ||
		c == MapKeyAudience ||
		c == MapKeySubject
}

// Groups returns the groups claim from the claims as slice of string.
//
// If groups are not in claims, ErrNotFound is returned. If groups in
// claims, but is empty/zero-value type, ErrEmptyClaimValue is returned.
// If groups claim exists, but is an invalid type, ErrInvalidClaims is returned.
//
// Method is permissive in terms of type, allowing groups to be keyed as
// []string, []byte, or string. However, it is recommended that consumers
// set their groups using SetGroups in order to ensure consistency and
// improve performance.
//
// If groups is type string, it is assumed CSV and returned using strings.Split.
func Groups(c jwt.MapClaims) ([]string, error) {

	groupsValue, ok := c[MapKeyGroups]
	if !ok {
		return nil, fmt.Errorf("%w: groups claim not found", ErrNotFound)
	}

	switch groups := groupsValue.(type) {
	case []string:
		if len(groups) == 0 {
			return nil, ErrEmptyClaimValue
		}
		return groups, nil

	case []any:
		if len(groups) == 0 {
			return nil, ErrEmptyClaimValue
		}
		groupStrings := make([]string, len(groups))
		for i, group := range groups {
			str, ok := group.(string)
			if !ok {
				return nil, fmt.Errorf(
					"%w: invalid group type in groups claim: must be string: got %T",
					ErrInvalidClaims, group,
				)
			}
			groupStrings[i] = str
		}
		return groupStrings, nil

	case string:
		if groups == "" {
			return nil, ErrEmptyClaimValue
		}
		return strings.Split(groups, ","), nil

	default:
		return nil, fmt.Errorf(
			"%w: groups claim is invalid type: must be []string, []any, or string: got %T",
			ErrInvalidClaims, groups,
		)
	}
}

// SetGroups sets the groups claim in the claims.
//
// Groups are not modified or normalized in any way, so consumers should be
// careful with whitespace and special characters like trailing slashes.
func SetGroups(c jwt.MapClaims, groups ...string) {
	c[MapKeyGroups] = groups
}

// DeleteGroups deletes the groups claim from the claims.
func DeleteGroups(c jwt.MapClaims) {
	delete(c, MapKeyGroups)
}

// MatchingGroups returns the subset of the groups claim that match the given match groups.
func MatchingGroups(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	tokenGroups, err := Groups(c)
	if err != nil {
		return nil, err
	}

	if len(tokenGroups) == 0 {
		return nil, errors.Join(ErrNotFound, ErrNoGroups)
	}

	groupsMap := make(map[string]bool)
	for _, aud := range normalizeStringSlice(tokenGroups...) {
		groupsMap[aud] = true
	}

	var filteredGroups []string
	for _, requestAud := range normalizeStringSlice(toMatch...) {
		if groupsMap[requestAud] {
			filteredGroups = append(filteredGroups, requestAud)
		}
	}

	if len(filteredGroups) == 0 {
		return nil, fmt.Errorf("%w: no groups after filtering", ErrNoGroups)
	}

	return filteredGroups, nil
}

// Audience returns the audience claim from the claims as slice of string.
//
// If audience is not in claims, ErrNotFound is returned. If audience is in
// claims, but is empty/zero-value type, ErrEmptyClaimValue is returned. If
// audience claim exists, but is an invalid type, ErrInvalidClaims is returned.
//
// Method is permissive in terms of type, allowing audience to be keyed as
// []string, []byte, or string. However, it is recommended that consumers
// set their audience using SetAudience in order to ensure consistency and
// improve performance.
//
// If audience is type string, it is assumed CSV and returned using strings.Split.
func Audience(c jwt.MapClaims) ([]string, error) {

	audienceValue, ok := c[MapKeyAudience]
	if !ok {
		return nil, fmt.Errorf("%w: audience claim not found", ErrNotFound)
	}

	switch audience := audienceValue.(type) {
	case []string:
		if len(audience) == 0 {
			return nil, ErrEmptyClaimValue
		}
		return audience, nil

	case []any:
		if len(audience) == 0 {
			return nil, ErrEmptyClaimValue
		}
		audienceStrings := make([]string, len(audience))
		for i, aud := range audience {
			str, ok := aud.(string)
			if !ok {
				return nil, fmt.Errorf(
					"%w: invalid audience type in audience claim: must be string: got %T",
					ErrInvalidClaims, aud,
				)
			}
			audienceStrings[i] = str
		}
		return audienceStrings, nil

	case string:
		if audience == "" {
			return nil, ErrEmptyClaimValue
		}
		return strings.Split(audience, ","), nil

	default:
		return nil, fmt.Errorf(
			"%w: audience claim is invalid type: must be []string, []any, or string: got %T",
			ErrInvalidClaims, audience,
		)
	}
}

// SetAudience sets the audience claim in the claims.
//
// Audience is not modified or normalized in any way, so consumers should be
// careful with whitespace and special characters like trailing slashes.
func SetAudience(c jwt.MapClaims, audience ...string) {
	c[MapKeyAudience] = audience
}

// DeleteAudience deletes the audience claim from the claims.
func DeleteAudience(c jwt.MapClaims) {
	delete(c, MapKeyAudience)
}

// MatchingAudience returns the subset of the audience claim that match the given match audiences.
func MatchingAudience(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	tokenAudiences, err := Audience(c)
	if err != nil {
		return nil, err
	}

	if len(tokenAudiences) == 0 {
		return nil, errors.Join(ErrNotFound, ErrNoAudience)
	}

	audienceMap := make(map[string]bool)
	for _, aud := range normalizeStringSlice(tokenAudiences...) {
		audienceMap[aud] = true
	}

	var filteredAudience []string
	for _, requestAud := range normalizeStringSlice(toMatch...) {
		if audienceMap[requestAud] {
			filteredAudience = append(filteredAudience, requestAud)
		}
	}

	if len(filteredAudience) == 0 {
		return nil, fmt.Errorf("%w: no audience after filtering", ErrNoAudience)
	}

	return filteredAudience, nil
}

// Roles returns the roles claim from the claims as slice of string.
//
// If roles are not in claims, ErrNotFound is returned. If roles are in
// claims, but are empty/zero-value type, ErrEmptyClaimValue is returned.
// If roles claim exists, but is an invalid type, ErrInvalidClaims is returned.
//
// Method is permissive in terms of type, allowing roles to be keyed as
// []string, []byte, or string. However, it is recommended that consumers
// set their roles using SetRoles in order to ensure consistency and
// improve performance.
//
// If roles is type string, it is assumed CSV and returned using strings.Split.
func Roles(c jwt.MapClaims) ([]string, error) {

	rolesValue, ok := c[MapKeyRoles]
	if !ok {
		return nil, fmt.Errorf("%w: roles claim not found", ErrNotFound)
	}

	switch roles := rolesValue.(type) {

	case []string:
		if len(roles) == 0 {
			return nil, ErrEmptyClaimValue
		}
		return roles, nil

	case []any:
		if len(roles) == 0 {
			return nil, ErrEmptyClaimValue
		}
		roleStrings := make([]string, len(roles))
		for i, role := range roles {
			str, ok := role.(string)
			if !ok {
				return nil, fmt.Errorf(
					"%w: invalid group type in groups claim: must be string: got %T",
					ErrInvalidClaims, role,
				)
			}
			roleStrings[i] = str
		}
		return roleStrings, nil

	case string:
		if roles == "" {
			return nil, ErrEmptyClaimValue
		}
		return strings.Split(roles, ","), nil

	default:
		return nil, fmt.Errorf(
			"%w: groups claim is invalid type: must be []string, []any, or string: got %T",
			ErrInvalidClaims, roles,
		)
	}
}

// SetRoles sets the roles claim in the claims.
//
// Roles are not modified or normalized in any way, so consumers should be
// careful with whitespace and special characters like trailing slashes.
func SetRoles(c jwt.MapClaims, roles ...string) {
	c[MapKeyRoles] = roles
}

// DeleteRoles deletes the roles claim from the claims.
func DeleteRoles(c jwt.MapClaims) {
	delete(c, MapKeyRoles)
}

// MatchingRoles returns the subset of the roles claim that matches the given match roles.
func MatchingRoles(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	tokenRoles, err := Roles(c)
	if err != nil {
		return nil, err
	}

	if len(tokenRoles) == 0 {
		return nil, errors.Join(ErrNotFound, ErrNoRoles)
	}

	rolesMap := make(map[string]bool)
	for _, aud := range normalizeStringSlice(tokenRoles...) {
		rolesMap[aud] = true
	}

	var filteredRoles []string
	for _, requestAud := range normalizeStringSlice(toMatch...) {
		if rolesMap[requestAud] {
			filteredRoles = append(filteredRoles, requestAud)
		}
	}

	if len(filteredRoles) == 0 {
		return nil, fmt.Errorf("%w: no roles after filtering", ErrNoRoles)
	}

	return filteredRoles, nil
}

// ID returns the id claim from the claims as string.
func ID(c jwt.MapClaims) (string, error) {
	id, ok := c[MapKeyID]
	if !ok {
		return "", fmt.Errorf("%w: id missing", ErrNotFound)
	}
	switch jti := id.(type) {
	case string:
		if jti == "" {
			return "", fmt.Errorf("%w: id empty", ErrEmptyClaimValue)
		}
		return jti, nil
	case []byte:
		if len(jti) == 0 {
			return "", fmt.Errorf("%w: id empty", ErrEmptyClaimValue)
		}
		return string(jti), nil
	default:
		return "", fmt.Errorf("%w: invalid id type: must be string or byte slice: got %T", ErrInvalidClaims, jti)
	}
}

// SetID sets the id claim in the claims as type string.
// Call is a no-op if the given ID is not an acceptable type.
//
// ID is not normalized in any way.
func SetID(c jwt.MapClaims, id any) {
	switch jti := id.(type) {
	case string:
		c[MapKeyID] = jti
	case []byte:
		c[MapKeyID] = string(jti)
	case uuid.UUID:
		c[MapKeyID] = jti.String()
	}
}

// DeleteID deletes the id claim from the claims.
func DeleteID(c jwt.MapClaims) {
	delete(c, MapKeyID)
}

// JTI returns the jti claim from the claims as string. It's an alias for ID.
func JTI(c jwt.MapClaims) (string, error) {
	return ID(c)
}

// SetJTI sets the jti claim in the claims. It's an alias for SetID.
//
// JTI is not normalized in any way.
func SetJTI(c jwt.MapClaims, jti string) {
	SetID(c, jti)
}

// DeleteJTI deletes the jti claim from the claims. It's an alias for DeleteID.
func DeleteJTI(c jwt.MapClaims) {
	DeleteID(c)
}

// Subject returns the subject claim from the claims as string.
func Subject(c jwt.MapClaims) (string, error) {
	subject, ok := c[MapKeySubject]
	if !ok {
		return "", fmt.Errorf("%w: subject missing", ErrNotFound)
	}
	switch sub := subject.(type) {
	case string:
		if sub == "" {
			return "", fmt.Errorf("%w: subject empty", ErrEmptyClaimValue)
		}
		return sub, nil
	case []byte:
		if len(sub) == 0 {
			return "", fmt.Errorf("%w: subject empty", ErrEmptyClaimValue)
		}
		return string(sub), nil
	default:
		return "", fmt.Errorf("%w: invalid subject type: must be string: got %T", ErrInvalidClaims, subject)
	}
}

// SetSubject sets the subject claim in the claims.
//
// Subject is not normalized in any way.
func SetSubject(c jwt.MapClaims, sub string) {
	c[MapKeySubject] = sub
}

// DeleteSubject deletes the subject claim from the claims.
func DeleteSubject(c jwt.MapClaims) {
	delete(c, MapKeySubject)
}

// Issuer returns the issuer claim from the claims as string.
func Issuer(c jwt.MapClaims) (string, error) {
	issuer, ok := c[MapKeyIssuer]
	if !ok {
		return "", fmt.Errorf("%w: issuer missing", ErrNotFound)
	}
	switch iss := issuer.(type) {
	case string:
		if iss == "" {
			return "", fmt.Errorf("%w: issuer empty", ErrEmptyClaimValue)
		}
		return iss, nil
	case []byte:
		if len(iss) == 0 {
			return "", fmt.Errorf("%w: issuer empty", ErrEmptyClaimValue)
		}
		return string(iss), nil
	default:
		return "", fmt.Errorf("%w: invalid issuer type: must be string: got %T", ErrInvalidClaims, issuer)
	}
}

// SetIssuer sets the issuer claim in the claims.
//
// Issuer is not normalized in any way.
func SetIssuer(c jwt.MapClaims, issuer string) {
	c[MapKeyIssuer] = issuer
}

// DeleteIssuer deletes the issuer claim from the claims.
func DeleteIssuer(c jwt.MapClaims) {
	delete(c, MapKeyIssuer)
}

// IssuedAt returns the issued at claim from the claims as time.Time.
func IssuedAt(c jwt.MapClaims) (time.Time, error) {

	iatValue, ok := c[MapKeyIssuedAt]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: issued at claim not found", ErrNotFound)
	}

	if iatValue == nil {
		return time.Time{}, fmt.Errorf("%w: issued at empty", ErrEmptyClaimValue)
	}

	ts, tsErr := timestamp(iatValue)
	if tsErr != nil {
		return time.Time{}, fmt.Errorf("normalizing issued at timestamp: %w", tsErr)
	}

	return ts, nil
}

// SetIssuedAt sets the issued at claim in the claims.
func SetIssuedAt(c jwt.MapClaims, iat time.Time) {
	c[MapKeyIssuedAt] = jwt.NewNumericDate(iat)
}

// DeleteIssuedAt deletes the issued at claim from the claims.
func DeleteIssuedAt(c jwt.MapClaims) {
	delete(c, MapKeyIssuedAt)
}

// IssuedAtBefore returns true if the issued at claim is before the given time.
//
// An error is only returned if the issued at claim is not found or has an invalid type.
func IssuedAtBefore(c jwt.MapClaims, before time.Time) (bool, error) {
	iat, err := IssuedAt(c)
	if err != nil {
		return false, err
	}
	return iat.Before(before), nil
}

// IssuedAtAfter returns true if the issued at claim is after the given time.
//
// An error is only returned if the issued at claim is not found or has an invalid type.
func IssuedAtAfter(c jwt.MapClaims, after time.Time) (bool, error) {
	iat, err := IssuedAt(c)
	if err != nil {
		return false, err
	}
	return iat.After(after), nil
}

// ExpiresAt returns the expires at claim from the claims as time.Time.
func ExpiresAt(c jwt.MapClaims) (time.Time, error) {

	expValue, ok := c[MapKeyExpiresAt]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: expires at claim not found", ErrNotFound)
	}

	if expValue == nil {
		return time.Time{}, fmt.Errorf("%w: expires at empty", ErrEmptyClaimValue)
	}

	ts, tsErr := timestamp(expValue)
	if tsErr != nil {
		return time.Time{}, fmt.Errorf("normalizing expires at timestamp: %w", tsErr)
	}

	return ts, nil
}

// SetExpiresAt sets the expires at claim in the claims.
func SetExpiresAt(c jwt.MapClaims, exp time.Time) {
	c[MapKeyExpiresAt] = jwt.NewNumericDate(exp)
}

// DeleteExpiresAt deletes the expires at claim from the claims.
func DeleteExpiresAt(c jwt.MapClaims) {
	delete(c, MapKeyExpiresAt)
}

// IsExpired returns true if the token has expired.
//
// An error is only returned if the expires at claim is not found or has an invalid type.
func IsExpired(c jwt.MapClaims) (is bool, expiresAt time.Time, err error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, time.Time{}, err
	}
	return exp.Before(time.Now()), exp, nil
}

// ExpiresBefore returns true if the token expires before the given time.
//
// An error is only returned if the expires at claim is not found or has an invalid type.
func ExpiresBefore(c jwt.MapClaims, before time.Time) (bool, error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, err
	}
	return exp.Before(before), nil
}

// ExpiresAfter returns true if the token expires after the given time.
//
// An error is only returned if the expires at claim is not found or has an invalid type.
func ExpiresAfter(c jwt.MapClaims, after time.Time) (bool, error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, err
	}
	return exp.After(after), nil
}

// NotBefore returns the not-before claim from the claims as int64.
func NotBefore(c jwt.MapClaims) (time.Time, error) {

	nbfValue, ok := c[MapKeyNotBefore]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: not before claim not found", ErrNotFound)
	}

	if nbfValue == nil {
		return time.Time{}, fmt.Errorf("%w: not before empty", ErrEmptyClaimValue)
	}

	ts, tsErr := timestamp(nbfValue)
	if tsErr != nil {
		return time.Time{}, fmt.Errorf("normalizing not before timestamp: %w", tsErr)
	}

	return ts, nil
}

// SetNotBefore sets the not-before claim in the claims.
func SetNotBefore(c jwt.MapClaims, nbf time.Time) {
	c[MapKeyNotBefore] = jwt.NewNumericDate(nbf)
}

// DeleteNotBefore deletes the not-before claim from the claims.
func DeleteNotBefore(c jwt.MapClaims) {
	delete(c, MapKeyNotBefore)
}

// IsNotBefore returns true if the token is otherwise valid, but not yet usable (not-before is in the future).
//
// An error is only returned if the not-before claim is not found or has an invalid type.
func IsNotBefore(c jwt.MapClaims) (is bool, nbf time.Time, err error) {
	nbf, err = NotBefore(c)
	if err != nil {
		return false, time.Time{}, err
	}
	return nbf.After(time.Now()), nbf, nil
}

// Name returns the name claim from the claims as string.
func Name(c jwt.MapClaims) (string, error) {
	name, ok := c[MapKeyName]
	if !ok {
		return "", fmt.Errorf("%w: name missing", ErrNotFound)
	}
	switch n := name.(type) {
	case string:
		if n == "" {
			return "", fmt.Errorf("%w: name empty", ErrEmptyClaimValue)
		}
		return n, nil
	case []byte:
		if len(n) == 0 {
			return "", fmt.Errorf("%w: name empty", ErrEmptyClaimValue)
		}
		return string(n), nil
	default:
		return "", fmt.Errorf("%w: invalid name type: must be string: got %T", ErrInvalidClaims, n)
	}
}

// SetName sets the name claim in the claims.
//
// Name is normalized, removing any leading or trailing whitespace.
func SetName(c jwt.MapClaims, name string) {
	c[MapKeyName] = strings.TrimSpace(name)
}

// DeleteName deletes the name claim from the claims.
func DeleteName(c jwt.MapClaims) {
	delete(c, MapKeyName)
}

// FirstName returns the first name claim from the claims as string.
func FirstName(c jwt.MapClaims) (string, error) {
	firstName, ok := c[MapKeyFirstName]
	if !ok {
		return "", fmt.Errorf("%w: first name missing", ErrNotFound)
	}
	switch n := firstName.(type) {
	case string:
		if n == "" {
			return "", fmt.Errorf("%w: first name empty", ErrEmptyClaimValue)
		}
		return n, nil
	case []byte:
		if len(n) == 0 {
			return "", fmt.Errorf("%w: first name empty", ErrEmptyClaimValue)
		}
		return string(n), nil
	default:
		return "", fmt.Errorf("%w: invalid first name type: must be string: got %T", ErrInvalidClaims, n)
	}
}

// SetFirstName sets the first name claim in the claims.
//
// First name is normalized, removing any leading or trailing whitespace.
func SetFirstName(c jwt.MapClaims, firstName string) {
	c[MapKeyFirstName] = strings.TrimSpace(firstName)
}

// DeleteFirstName deletes the first name claim from the claims.
func DeleteFirstName(c jwt.MapClaims) {
	delete(c, MapKeyFirstName)
}

// LastName returns the last name claim from the claims as string.
func LastName(c jwt.MapClaims) (string, error) {
	lastName, ok := c[MapKeyLastName]
	if !ok {
		return "", fmt.Errorf("%w: last name missing", ErrNotFound)
	}
	switch n := lastName.(type) {
	case string:
		if n == "" {
			return "", fmt.Errorf("%w: last name empty", ErrEmptyClaimValue)
		}
		return n, nil
	case []byte:
		if len(n) == 0 {
			return "", fmt.Errorf("%w: last name empty", ErrEmptyClaimValue)
		}
		return string(n), nil
	default:
		return "", fmt.Errorf("%w: invalid last name type: must be string: got %T", ErrInvalidClaims, n)
	}
}

// SetLastName sets the last name claim in the claims.
//
// First name is normalized, removing any leading or trailing whitespace.
func SetLastName(c jwt.MapClaims, lastName string) {
	c[MapKeyLastName] = strings.TrimSpace(lastName)
}

// DeleteLastName deletes the last name claim from the claims.
func DeleteLastName(c jwt.MapClaims) {
	delete(c, MapKeyLastName)
}

// Username returns the username claim from the claims as string.
func Username(c jwt.MapClaims) (string, error) {
	username, ok := c[MapKeyUsername]
	if !ok {
		return "", fmt.Errorf("%w: username missing", ErrNotFound)
	}
	switch u := username.(type) {
	case string:
		if u == "" {
			return "", fmt.Errorf("%w: username empty", ErrEmptyClaimValue)
		}
		return u, nil
	case []byte:
		if len(u) == 0 {
			return "", fmt.Errorf("%w: username empty", ErrEmptyClaimValue)
		}
		return string(u), nil
	default:
		return "", fmt.Errorf("%w: invalid username type: must be string: got %T", ErrInvalidClaims, u)
	}
}

// SetUsername sets the username claim in the claims.
//
// Username is normalized, removing any leading or trailing whitespace.
func SetUsername(c jwt.MapClaims, username string) {
	c[MapKeyUsername] = strings.TrimSpace(username)
}

// DeleteUsername deletes the username claim from the claims.
func DeleteUsername(c jwt.MapClaims) {
	delete(c, MapKeyUsername)
}

// LDAP returns the username claim from the claims as string. It's an alias for Username.
func LDAP(c jwt.MapClaims) (string, error) {
	return Username(c)
}

// SetLDAP sets the username claim in the claims. It's an alias for SetUsername.
//
// LDAP is normalized, removing any leading or trailing whitespace.
func SetLDAP(c jwt.MapClaims, ldap string) {
	SetUsername(c, ldap)
}

// DeleteLDAP deletes the username claim from the claims. It's an alias for DeleteUsername.
func DeleteLDAP(c jwt.MapClaims) {
	DeleteUsername(c)
}

// UserType returns the user type claim from the claims as string.
func UserType(c jwt.MapClaims) (string, error) {
	userType, ok := c[MapKeyUserType]
	if !ok {
		return "", fmt.Errorf("%w: user type missing", ErrNotFound)
	}
	switch u := userType.(type) {
	case string:
		if u == "" {
			return "", fmt.Errorf("%w: user type empty", ErrEmptyClaimValue)
		}
		return u, nil
	case []byte:
		if len(u) == 0 {
			return "", fmt.Errorf("%w: user type empty", ErrEmptyClaimValue)
		}
		return string(u), nil
	default:
		return "", fmt.Errorf("%w: invalid user type type: must be string: got %T", ErrInvalidClaims, u)
	}
}

// SetUserType sets the user type claim in the claims.
//
// User type is normalized, removing any leading or trailing whitespace.
func SetUserType(c jwt.MapClaims, userType string) {
	c[MapKeyUserType] = strings.TrimSpace(userType)
}

// DeleteUserType deletes the user type claim from the claims.
func DeleteUserType(c jwt.MapClaims) {
	delete(c, MapKeyUserType)
}

// Email returns the email claim from the claims as string.
func Email(c jwt.MapClaims) (string, error) {
	email, ok := c[MapKeyEmail]
	if !ok {
		return "", fmt.Errorf("%w: email missing", ErrNotFound)
	}
	switch e := email.(type) {
	case string:
		if e == "" {
			return "", fmt.Errorf("%w: email empty", ErrEmptyClaimValue)
		}
		return e, nil
	case []byte:
		if len(e) == 0 {
			return "", fmt.Errorf("%w: email empty", ErrEmptyClaimValue)
		}
		return string(e), nil
	default:
		return "", fmt.Errorf("%w: invalid email type: must be string: got %T", ErrInvalidClaims, e)
	}
}

// SetEmail sets the email claim in the claims.
//
// Email is normalized, removing any leading or trailing whitespace.
func SetEmail(c jwt.MapClaims, email string) {
	c[MapKeyEmail] = strings.TrimSpace(email)
}

// DeleteEmail deletes the email claim from the claims.
func DeleteEmail(c jwt.MapClaims) {
	delete(c, MapKeyEmail)
}

// CR returns the cr claim from the claims as string.
func CR(c jwt.MapClaims) (string, error) {
	cr, ok := c[MapKeyCR]
	if !ok {
		return "", fmt.Errorf("%w: cr missing", ErrNotFound)
	}
	switch chgReq := cr.(type) {
	case string:
		if chgReq == "" {
			return "", fmt.Errorf("%w: cr empty", ErrEmptyClaimValue)
		}
		return chgReq, nil
	case []byte:
		if len(chgReq) == 0 {
			return "", fmt.Errorf("%w: cr empty", ErrEmptyClaimValue)
		}
		return string(chgReq), nil
	default:
		return "", fmt.Errorf("%w: invalid cr type: must be string: got %T", ErrInvalidClaims, chgReq)
	}
}

// SetCR sets the cr claim in the claims.
//
// CR is not normalized in any way.
func SetCR(c jwt.MapClaims, cr string) {
	c[MapKeyCR] = cr
}

// DeleteCR deletes the cr claim from the claims.
func DeleteCR(c jwt.MapClaims) {
	delete(c, MapKeyCR)
}

// TelephoneNumber returns the telephone number claim from the claims as string.
func TelephoneNumber(c jwt.MapClaims) (string, error) {
	telephoneNumber, ok := c[MapKeyTelephoneNumber]
	if !ok {
		return "", fmt.Errorf("%w: telephone number missing", ErrNotFound)
	}
	switch tele := telephoneNumber.(type) {
	case string:
		if tele == "" {
			return "", fmt.Errorf("%w: telephone number empty", ErrEmptyClaimValue)
		}
		return tele, nil
	default:
		return "", fmt.Errorf("%w: invalid telephone number type: must be string: got %T", ErrInvalidClaims, tele)
	}
}

// SetTelephoneNumber sets the telephone number claim in the claims.
//
// Telephone number is normalized, removing any leading or trailing whitespace.
func SetTelephoneNumber(c jwt.MapClaims, telephoneNumber string) {
	c[MapKeyTelephoneNumber] = strings.TrimSpace(telephoneNumber)
}

// DeleteTelephoneNumber deletes the telephone number claim from the claims.
func DeleteTelephoneNumber(c jwt.MapClaims) {
	delete(c, MapKeyTelephoneNumber)
}

// TokenType returns the token type claim from the claims as string.
func TokenType(c jwt.MapClaims) (string, error) {
	tokenType, ok := c[MapKeyTokenType]
	if !ok {
		return "", fmt.Errorf("%w: token type missing", ErrNotFound)
	}
	switch tt := tokenType.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: token type empty", ErrEmptyClaimValue)
		}
		return tt, nil
	default:
		return "", fmt.Errorf("%w: invalid token type type: must be string: got %T", ErrInvalidClaims, tt)
	}
}

// SetTokenType sets the token type claim in the claims.
//
// Token type is normalized, removing any leading or trailing whitespace.
func SetTokenType(c jwt.MapClaims, tokenType string) {
	c[MapKeyTokenType] = strings.TrimSpace(tokenType)
}

// DeleteTokenType deletes the token type claim from the claims.
func DeleteTokenType(c jwt.MapClaims) {
	delete(c, MapKeyTokenType)
}

// LocationNumber returns the location number claim from the claims as string.
func LocationNumber(c jwt.MapClaims) (string, error) {
	locationNumber, ok := c[MapKeyLocationNumber]
	if !ok {
		return "", fmt.Errorf("%w: location number missing", ErrNotFound)
	}
	switch tt := locationNumber.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: location number empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: location number empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	case int:
		return strconv.Itoa(tt), nil
	case int64:
		return strconv.FormatInt(tt, 10), nil
	case float64:
		return strconv.FormatFloat(tt, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf(
			"%w: invalid location number type: must be string, []byte, int, int64, or float64: got %T",
			ErrInvalidClaims, tt,
		)
	}
}

// SetLocationNumber sets the location number claim in the claims.
//
// Location number is normalized, removing any leading or trailing whitespace.
func SetLocationNumber(c jwt.MapClaims, locationNumber string) {
	c[MapKeyLocationNumber] = strings.TrimSpace(locationNumber)
}

// DeleteLocationNumber deletes the location number claim from the claims.
func DeleteLocationNumber(c jwt.MapClaims) {
	delete(c, MapKeyLocationNumber)
}

// LocationType returns the location type claim from the claims as string.
func LocationType(c jwt.MapClaims) (string, error) {
	locationType, ok := c[MapKeyLocationType]
	if !ok {
		return "", fmt.Errorf("%w: location type missing", ErrNotFound)
	}
	switch tt := locationType.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: location type empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: location type empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	default:
		return "", fmt.Errorf("%w: invalid location type type: must be string or []byte: got %T", ErrInvalidClaims, tt)
	}
}

// SetLocationType sets the location type claim in the claims.
//
// Location type is normalized, removing any leading or trailing whitespace.
func SetLocationType(c jwt.MapClaims, locationType string) {
	c[MapKeyLocationType] = strings.TrimSpace(locationType)
}

// DeleteLocationType deletes the location type claim from the claims.
func DeleteLocationType(c jwt.MapClaims) {
	delete(c, MapKeyLocationType)
}

// DepartmentNumber returns the department number claim from the claims as string.
func DepartmentNumber(c jwt.MapClaims) (string, error) {
	department, ok := c[MapKeyDepartmentNumber]
	if !ok {
		return "", fmt.Errorf("%w: department number missing", ErrNotFound)
	}
	switch tt := department.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: department number empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: department number empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	case int:
		return strconv.Itoa(tt), nil
	case int64:
		return strconv.FormatInt(tt, 10), nil
	case float64:
		return strconv.FormatFloat(tt, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf(
			"%w: invalid department number type: must be string, []byte, int, int64, or float64: got %T",
			ErrInvalidClaims, tt,
		)
	}
}

// SetDepartmentNumber sets the department number claim in the claims.
//
// Department number is normalized, removing any leading or trailing whitespace.
func SetDepartmentNumber(c jwt.MapClaims, department string) {
	c[MapKeyDepartmentNumber] = strings.TrimSpace(department)
}

// DeleteDepartmentNumber deletes the department number claim from the claims.
func DeleteDepartmentNumber(c jwt.MapClaims) {
	delete(c, MapKeyDepartmentNumber)
}

// JobDesignation returns the job designation claim from the claims as string.
func JobDesignation(c jwt.MapClaims) (string, error) {
	jobDesignation, ok := c[MapKeyJobDesignation]
	if !ok {
		return "", fmt.Errorf("%w: job designation missing", ErrNotFound)
	}
	switch tt := jobDesignation.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: job designation empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: job designation empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	case int:
		return strconv.Itoa(tt), nil
	case int64:
		return strconv.FormatInt(tt, 10), nil
	case float64:
		return strconv.FormatFloat(tt, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf(
			"%w: invalid job designation type: must be string, []byte, int, int64, or float64: got %T",
			ErrInvalidClaims, tt,
		)
	}
}

// SetJobDesignation sets the job designation claim in the claims.
//
// Job designation is normalized, removing any leading or trailing whitespace.
func SetJobDesignation(c jwt.MapClaims, jobDesignation string) {
	c[MapKeyJobDesignation] = strings.TrimSpace(jobDesignation)
}

// DeleteJobDesignation deletes the job designation claim from the claims.
func DeleteJobDesignation(c jwt.MapClaims) {
	delete(c, MapKeyJobDesignation)
}

// JobTitle returns the job title claim from the claims as string.
func JobTitle(c jwt.MapClaims) (string, error) {
	jobTitle, ok := c[MapKeyJobTitle]
	if !ok {
		return "", fmt.Errorf("%w: job title missing", ErrNotFound)
	}
	switch tt := jobTitle.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: job title empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: job title empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	default:
		return "", fmt.Errorf("%w: invalid job title type: must be string or []byte: got %T", ErrInvalidClaims, tt)
	}
}

// SetJobTitle sets the job title claim in the claims.
//
// Job title is normalized, removing any leading or trailing whitespace.
func SetJobTitle(c jwt.MapClaims, jobTitle string) {
	c[MapKeyJobTitle] = strings.TrimSpace(jobTitle)
}

// DeleteJobTitle deletes the job title claim from the claims.
func DeleteJobTitle(c jwt.MapClaims) {
	delete(c, MapKeyJobTitle)
}

// SupervisorOrgCode returns the supervisor org code claim from the claims as string.
func SupervisorOrgCode(c jwt.MapClaims) (string, error) {
	supervisorOrgCode, ok := c[MapKeySupervisorOrgCode]
	if !ok {
		return "", fmt.Errorf("%w: supervisor org code missing", ErrNotFound)
	}
	switch tt := supervisorOrgCode.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: supervisor org code empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: supervisor org code empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	case int:
		return strconv.Itoa(tt), nil
	case int64:
		return strconv.FormatInt(tt, 10), nil
	case float64:
		return strconv.FormatFloat(tt, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf(
			"%w: invalid supervisor org code type: must be string, []byte, int, int64, or float64: got %T",
			ErrInvalidClaims, tt,
		)
	}
}

// SetSupervisorOrgCode sets the supervisor org code claim in the claims.
//
// Supervisor org code is normalized, removing any leading or trailing whitespace.
func SetSupervisorOrgCode(c jwt.MapClaims, supervisorOrgCode string) {
	c[MapKeySupervisorOrgCode] = strings.TrimSpace(supervisorOrgCode)
}

// DeleteSupervisorOrgCode deletes the supervisor org code claim from the claims.
func DeleteSupervisorOrgCode(c jwt.MapClaims) {
	delete(c, MapKeySupervisorOrgCode)
}

// PreferredLanguage returns the preferred language claim from the claims as string.
func PreferredLanguage(c jwt.MapClaims) (string, error) {
	preferredLanguage, ok := c[MapKeyPreferredLanguage]
	if !ok {
		return "", fmt.Errorf("%w: preferred language missing", ErrNotFound)
	}
	switch tt := preferredLanguage.(type) {
	case string:
		if tt == "" {
			return "", fmt.Errorf("%w: preferred language empty", ErrEmptyClaimValue)
		}
		return tt, nil
	case []byte:
		if len(tt) == 0 {
			return "", fmt.Errorf("%w: preferred language empty", ErrEmptyClaimValue)
		}
		return string(tt), nil
	default:
		return "", fmt.Errorf("%w: invalid preferred language type: must be string or []byte: got %T", ErrInvalidClaims, tt)
	}
}

// SetPreferredLanguage sets the preferred language claim in the claims.
//
// Preferred language is normalized, removing any leading or trailing whitespace.
func SetPreferredLanguage(c jwt.MapClaims, preferredLanguage string) {
	c[MapKeyPreferredLanguage] = strings.TrimSpace(preferredLanguage)
}

// DeletePreferredLanguage deletes the preferred language claim from the claims.
func DeletePreferredLanguage(c jwt.MapClaims) {
	delete(c, MapKeyPreferredLanguage)
}

// normalizeString returns the normalized string, removing leading and trailing
// whitespace and ensuring that entries that terminate in a trailing slash(es)
// are normalized to the same entry without the trailing slash(es).
func normalizedString(s string) string {
	normalized := strings.TrimSpace(s)
	normalized = strings.TrimRight(normalized, "/")
	// We trim a second time, because it is possible (though highly unlikely)
	// that a trailing slash was preceded by whitespace, which is removed here.
	return strings.TrimSpace(normalized)
}

// normalizeStringSlice returns the normalized slice, removing leading and
// trailing whitespace and ensuring that entries that terminate with a trailing
// slash(es) are normalized to the same entry without the trailing slash(es).
func normalizeStringSlice(s ...string) []string {
	slice := make([]string, len(s))
	for i := 0; i < len(s); i++ {
		slice[i] = normalizedString(s[i])
	}
	return slice
}
