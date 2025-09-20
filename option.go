// Copyright 2023 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbin

import (
	"context"
	"errors"
	"log"
	"regexp"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

// LookupHandler is used to look up current subject in runtime.
// If it can not find anything, just return an empty string.
type LookupHandler func(ctx context.Context, c *app.RequestContext) string

// DomainLookupHandler is used to look up current subject and domain in runtime.
// If it can not find anything, just return empty strings.
type DomainLookupHandler func(ctx context.Context, c *app.RequestContext) (subject, domain string)

// Logic is the logical operation (AND/OR) used in permission checks
// in case multiple permissions or roles are specified.
type Logic int

// PermissionParserFunc is used for parsing the permission
// to extract object and action usually
type PermissionParserFunc func(str string) []string

const (
	AND Logic = iota
	OR
	CUSTOM
)

const (
	DefaultPermissionSeparator = ":"
	MaxDomainNameLength        = 32
	MaxSubjectNameLength       = 64
)

var (
	errLookupNil       = errors.New("[Casbin] Lookup is nil")
	errDomainLookupNil = errors.New("[Casbin] DomainLookup is nil")

	// Domain validation regex: alphanumeric, underscore, hyphen, 1-32 chars
	domainNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)
	// Subject validation regex: alphanumeric, underscore, dot, 1-64 chars
	subjectNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)
)

// Option is the only struct that can be used to set Options.
type Option struct {
	F func(o *Options)
}

type Options struct {
	// Logic is the logical operation (AND/OR) used in permission checks
	// in case multiple permissions or roles are specified.
	// Optional. Default: AND
	Logic Logic

	// PermissionParserFunc is used for parsing the permission
	// to extract object and action usually
	// Optional. Default: PermissionParserWithSeparator(":")
	PermissionParser PermissionParserFunc
	// PermissionSeparator permission parsing separator
	PermissionSeparator string

	// EnableDomains enables multi-tenant domain support
	// Optional. Default: false
	EnableDomains bool

	// EnableAuditLog enables security audit logging for authorization decisions
	// Optional. Default: false
	EnableAuditLog bool

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(ctx context.Context, c *app.RequestContext) {
	//		c.AbortWithStatus(consts.StatusUnauthorized)
	//	},
	Unauthorized app.HandlerFunc

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(ctx context.Context, c *app.RequestContext) {
	//		c.AbortWithStatus(consts.StatusForbidden)
	//	},
	Forbidden app.HandlerFunc
}

// Apply to apply options.
func (o *Options) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

// ValidateDomainName validates if the domain name follows security rules
func ValidateDomainName(domain string) error {
	if len(domain) == 0 || len(domain) > MaxDomainNameLength {
		return errors.New("invalid domain name length")
	}

	if !domainNameRegex.MatchString(domain) {
		return errors.New("invalid domain name format")
	}

	return nil
}

// ValidateSubjectName validates if the subject name follows security rules
func ValidateSubjectName(subject string) error {
	if len(subject) == 0 || len(subject) > MaxSubjectNameLength {
		return errors.New("invalid subject name length")
	}

	if !subjectNameRegex.MatchString(subject) {
		return errors.New("invalid subject name format")
	}

	return nil
}

var OptionsDefault = Options{
	Logic:               AND,
	PermissionParser:    PermissionParserWithSeparator(DefaultPermissionSeparator),
	PermissionSeparator: DefaultPermissionSeparator,
	EnableDomains:       false,
	EnableAuditLog:      false,
	Unauthorized: func(ctx context.Context, c *app.RequestContext) {
		c.AbortWithStatus(consts.StatusUnauthorized)
	},
	Forbidden: func(ctx context.Context, c *app.RequestContext) {
		c.AbortWithStatus(consts.StatusForbidden)
	},
}

func NewOptions(opts ...Option) *Options {
	options := &Options{
		Logic:               OptionsDefault.Logic,
		PermissionParser:    OptionsDefault.PermissionParser,
		PermissionSeparator: OptionsDefault.PermissionSeparator,
		EnableDomains:       OptionsDefault.EnableDomains,
		EnableAuditLog:      OptionsDefault.EnableAuditLog,
		Unauthorized:        OptionsDefault.Unauthorized,
		Forbidden:           OptionsDefault.Forbidden,
	}
	options.Apply(opts)
	return options
}

// WithLogic sets the logical operator used in permission or role checks.
func WithLogic(logic Logic) Option {
	return Option{
		F: func(o *Options) {
			o.Logic = logic
		},
	}
}

// WithPermissionParser sets parsing the permission func.
// Attention: It is only enabled when logic is `AND` or `OR`
func WithPermissionParser(pp PermissionParserFunc) Option {
	return Option{
		F: func(o *Options) {
			o.PermissionParser = pp
		},
	}
}

// WithPermissionParserSeparator sets permission parsing separator
func WithPermissionParserSeparator(sep string) Option {
	return Option{
		F: func(o *Options) {
			o.PermissionParser = PermissionParserWithSeparator(sep)
			o.PermissionSeparator = sep
		},
	}
}

// WithUnauthorized defines the response body for unauthorized responses.
func WithUnauthorized(u app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.Unauthorized = u
		},
	}
}

// WithForbidden defines the response body for forbidden responses.
func WithForbidden(f app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.Forbidden = f
		},
	}
}

// WithEnableDomains enables multi-tenant domain support.
func WithEnableDomains(enable bool) Option {
	return Option{
		F: func(o *Options) {
			o.EnableDomains = enable
		},
	}
}

// WithEnableAuditLog enables security audit logging for authorization decisions.
func WithEnableAuditLog(enable bool) Option {
	return Option{
		F: func(o *Options) {
			o.EnableAuditLog = enable
		},
	}
}

// LogAuthorizationDecision logs authorization decisions for audit purposes
func LogAuthorizationDecision(sub, domain, obj, act string, allowed bool, err error) {
	if err != nil {
		log.Printf("[CASBIN_AUDIT] Authorization error: subject=%s domain=%s object=%s action=%s error=%v",
			sub, domain, obj, act, err)
	} else {
		status := "ALLOWED"
		if !allowed {
			status = "DENIED"
		}
		log.Printf("[CASBIN_AUDIT] Authorization decision: subject=%s domain=%s object=%s action=%s result=%s",
			sub, domain, obj, act, status)
	}
}

// PermissionParserWithSeparator is a permission parser with separator.
func PermissionParserWithSeparator(sep string) PermissionParserFunc {
	return func(str string) []string {
		return strings.Split(str, sep)
	}
}
