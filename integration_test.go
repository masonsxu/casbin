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
	"net/http"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

// TestFullWorkflowIntegration tests the complete authentication and authorization workflow
func TestFullWorkflowIntegration(t *testing.T) {
	// Test single-tenant workflow
	t.Run("SingleTenantWorkflow", func(t *testing.T) {
		middleware, err := NewCasbinMiddleware(modelFile, simplePolicy, LookupAlice)
		assert.Nil(t, err)

		r := server.Default()
		r.GET("/protected", middleware.RequiresPermissions("book:read", WithLogic(AND)), func(ctx context.Context, c *app.RequestContext) {
			c.String(http.StatusOK, "success")
		})

		// Test successful access
		rsp := ut.PerformRequest(r.Engine, "GET", "/protected", nil)
		assert.DeepEqual(t, consts.StatusOK, rsp.Code)
		assert.DeepEqual(t, "success", rsp.Body.String())

		// Test with audit logging
		r2 := server.Default()
		r2.GET("/protected", middleware.RequiresPermissions("book:read", WithLogic(AND), WithEnableAuditLog(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(http.StatusOK, "success")
		})

		rsp2 := ut.PerformRequest(r2.Engine, "GET", "/protected", nil)
		assert.DeepEqual(t, consts.StatusOK, rsp2.Code)
	})

	// Test multi-tenant workflow
	t.Run("MultiTenantWorkflow", func(t *testing.T) {
		middleware, err := NewCasbinMiddlewareFromEnforcerWithDomain(
			func() *casbin.Enforcer {
				e, _ := casbin.NewEnforcer(modelFileMultiTenant, multiTenantPolicy)
				return e
			}(),
			DomainLookupAliceTenant1,
		)
		assert.Nil(t, err)

		r := server.Default()
		r.GET("/protected", middleware.RequiresPermissions("book:read", WithEnableDomains(true), WithEnableAuditLog(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(http.StatusOK, "multi-tenant success")
		})

		// Test successful multi-tenant access
		rsp := ut.PerformRequest(r.Engine, "GET", "/protected", nil)
		assert.DeepEqual(t, consts.StatusOK, rsp.Code)
		assert.DeepEqual(t, "multi-tenant success", rsp.Body.String())
	})
}

// TestSecurityValidation tests security validation features
func TestSecurityValidation(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		user   string
		valid  bool
	}{
		{"valid domain and user", "tenant1", "alice", true},
		{"invalid domain - too long", "a very long domain name that exceeds the maximum length", "alice", false},
		{"invalid domain - special chars", "tenant@1", "alice", false},
		{"invalid user - too long", "tenant1", "a_very_long_username_that_exceeds_the_maximum_allowed_length_limit", false},
		{"invalid user - special chars", "tenant1", "alice@example.com", false},
		{"empty domain", "", "alice", false},
		{"empty user", "tenant1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainErr := ValidateDomainName(tt.domain)
			userErr := ValidateSubjectName(tt.user)

			if tt.valid {
				assert.Nil(t, domainErr)
				assert.Nil(t, userErr)
			} else {
				// At least one validation should fail
				assert.True(t, domainErr != nil || userErr != nil)
			}
		})
	}
}
