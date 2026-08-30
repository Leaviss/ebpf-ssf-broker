package caep

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func sampleSubject() SubjectId {
	return SubjectId{
		Format: "uri",
		URI:    "spiffe://example.org/ns/default/sa/service-a",
	}
}

func sampleEvent() CAEPEvent {
	return CAEPEvent{
		EventTimeStampNs: 1_700_000_000_123_456_789,
		InitiatingEntity: "policy",
	}
}

func TestNewSet(t *testing.T) {
	iat := time.Unix(1_700_000_123, 0)
	subject := sampleSubject()
	event := sampleEvent()

	got := NewSet("translator", "actuator", "jti-1", iat, subject, event)

	if got.Issuer != "translator" {
		t.Errorf("Issuer = %q, want %q", got.Issuer, "translator")
	}
	if len(got.Audience) != 1 || got.Audience[0] != "actuator" {
		t.Errorf("Audience = %v, want [actuator]", got.Audience)
	}
	if got.ID != "jti-1" {
		t.Errorf("ID = %q, want %q", got.ID, "jti-1")
	}
	if got.IssuedAt == nil || !got.IssuedAt.Time.Equal(iat) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, iat)
	}
	if got.SubId != subject {
		t.Errorf("SubId = %+v, want %+v", got.SubId, subject)
	}
	if got.Events != event {
		t.Errorf("Events = %+v, want %+v", got.Events, event)
	}
}

func TestEncodeUnsignedUsesAlgNone(t *testing.T) {
	set := NewSet("translator", "actuator", "jti-1", time.Unix(1_700_000_123, 0), sampleSubject(), sampleEvent())

	raw, err := set.EncodeUnsigned()
	if err != nil {
		t.Fatalf("EncodeUnsigned() error = %v", err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), raw)
	}
	if parts[2] != "" {
		t.Errorf("signature segment = %q, want empty (alg:none)", parts[2])
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshaling header: %v", err)
	}
	if header.Alg != "none" {
		t.Errorf("header alg = %q, want %q", header.Alg, "none")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	// JWT NumericDate has second precision, so use a whole-second iat.
	iat := time.Unix(1_700_000_123, 0)
	subject := sampleSubject()
	event := sampleEvent()
	want := NewSet("translator", "actuator", "jti-round-trip", iat, subject, event)

	raw, err := want.EncodeUnsigned()
	if err != nil {
		t.Fatalf("EncodeUnsigned() error = %v", err)
	}

	got, err := DecodeUnsigned(raw)
	if err != nil {
		t.Fatalf("DecodeUnsigned() error = %v", err)
	}

	if got.Issuer != want.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, want.Issuer)
	}
	if len(got.Audience) != 1 || got.Audience[0] != want.Audience[0] {
		t.Errorf("Audience = %v, want %v", got.Audience, want.Audience)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if got.IssuedAt == nil || !got.IssuedAt.Time.Equal(iat) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, iat)
	}
	if got.SubId != subject {
		t.Errorf("SubId = %+v, want %+v", got.SubId, subject)
	}
	if got.Events != event {
		t.Errorf("Events = %+v, want %+v", got.Events, event)
	}
}

func TestDecodeUnsignedRejectsSignedToken(t *testing.T) {
	// A token signed with HS256 must be rejected: DecodeUnsigned only accepts alg:none.
	claims := NewSet("translator", "actuator", "jti-signed", time.Unix(1_700_000_123, 0), sampleSubject(), sampleEvent())
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("signing HS256 token: %v", err)
	}

	if _, err := DecodeUnsigned(signed); err == nil {
		t.Error("DecodeUnsigned() accepted an HS256-signed token, want error")
	}
}

func TestDecodeUnsignedRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"not a jwt", "not-a-jwt"},
		{"two segments", "aaa.bbb"},
		{"garbage payload", "aaa.bbb.ccc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeUnsigned(tt.raw); err == nil {
				t.Errorf("DecodeUnsigned(%q) = nil error, want error", tt.raw)
			}
		})
	}
}
