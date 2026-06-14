package gcp

import "strings"

// memberID returns the stable external id used to key an identity for an IAM member. Service
// accounts resolve to their bare email so an impersonator that is itself a collected SA maps to the
// same identity; other member types keep their full "type:value" form for uniqueness.
func memberID(m string) string {
	typ, id := parseMember(m)
	if id == "" {
		return m // allUsers / allAuthenticatedUsers
	}
	if typ == "serviceAccount" {
		return id
	}
	return m
}

// shortKeyID extracts the key id from a full key resource name
// (projects/P/serviceAccounts/E/keys/KEY_ID).
func shortKeyID(name string) string {
	if i := strings.LastIndex(name, "/keys/"); i >= 0 {
		return name[i+len("/keys/"):]
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// shortEmail returns the local part of a service-account email for a friendly role label.
func shortEmail(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}
