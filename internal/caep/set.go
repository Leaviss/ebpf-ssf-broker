// Package caep is the translator <-> actuator wire contract: an RFC 8417 SET,
// carried as a JWT with an RFC 9493 subject and a CAEP event.
package caep

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SubjectId struct {
	Format string `json:"format"` // always "uri" here
	URI    string `json:"uri"`    // the workload's SPIFFE ID
}

type CAEPEvent struct {
	// T0 — when the Tetragon policy matched in the kernel. Nanoseconds, not the
	// CAEP-conventional seconds: the span this SET is evidence for is sub-second,
	// so second resolution would quantise away the measurement. The unit is in
	// the name and on the wire so nothing has to infer it.
	EventTimeStampNs int64  `json:"event_timestamp_ns"`
	InitiatingEntity string `json:"initiating_entity"` // always "policy" here
}

type SetClaims struct {
	jwt.RegisteredClaims
	SubId  SubjectId `json:"sub_id"` // Subject
	Events CAEPEvent `json:"events"` // Security Event
}

// NewSet builds a SET for an already-resolved subject and event.
func NewSet(iss, aud, jti string, iat time.Time, subject SubjectId, event CAEPEvent) SetClaims {
	return SetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(iat), // when the translator minted the SET
		},
		SubId:  subject,
		Events: event,
	}
}

// EncodeUnsigned serializes the SET as an unsigned JWT (alg: none).
func (c SetClaims) EncodeUnsigned() (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, c)
	return tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

// DecodeUnsigned parses an unsigned JWT (alg: none) SET back into its claims.
func DecodeUnsigned(rawData string) (SetClaims, error) {
	var claims SetClaims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"none"}))
	if _, err := parser.ParseWithClaims(rawData, &claims, func(*jwt.Token) (any, error) {
		return jwt.UnsafeAllowNoneSignatureType, nil
	}); err != nil {
		return SetClaims{}, err
	}
	return claims, nil
}
