package main

import (
	"context"
	"log"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/hertz-contrib/casbin"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func main() {
	h := server.Default()

	// Using sessions for multi-tenant authentication
	store := cookie.NewStore([]byte("secret"))
	h.Use(sessions.New("session", store))

	// Initialize multi-tenant Casbin middleware
	auth, err := casbin.NewCasbinMiddleware("config/model_multi_tenant.conf", "config/policy_multi_tenant.csv", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create domain-aware middleware
	domainAuth, err := casbin.NewCasbinMiddlewareFromEnforcerWithDomain(auth.Enforcer(), subjectAndDomainFromSession)
	if err != nil {
		log.Fatal(err)
	}

	// Login endpoint - sets both user and tenant in session
	h.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		user := string(c.PostForm("user"))
		tenant := string(c.PostForm("tenant"))

		// Verify username, password and tenant access
		// ... authentication logic here ...

		// Store current subject and domain in session
		session := sessions.Default(c)
		session.Set("user", user)
		session.Set("tenant", tenant)
		err := session.Save()
		if err != nil {
			log.Printf("Failed to save session: %v", err)
			c.String(500, "Session save failed")
			return
		}
		c.String(200, "Login successful for user %s in tenant %s", user, tenant)
	})

	// Tenant1 routes - book management
	tenant1 := h.Group("/tenant1")
	{
		// Admin can read/write/delete books in tenant1
		tenant1.GET("/book/read", domainAuth.RequiresPermissions("book:read", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Reading book in tenant1")
		})

		tenant1.POST("/book/write", domainAuth.RequiresPermissions("book:write", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Writing book in tenant1")
		})

		tenant1.DELETE("/book/delete", domainAuth.RequiresPermissions("book:delete", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Deleting book in tenant1")
		})

		// Role-based access
		tenant1.POST("/admin-action", domainAuth.RequiresRoles("admin", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Admin action in tenant1")
		})
	}

	// Tenant2 routes - article management
	tenant2 := h.Group("/tenant2")
	{
		// Different resource (articles) with different roles
		tenant2.GET("/article/read", domainAuth.RequiresPermissions("article:read", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Reading article in tenant2")
		})

		tenant2.POST("/article/write", domainAuth.RequiresPermissions("article:write", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Writing article in tenant2")
		})

		// Complex permission logic
		tenant2.POST("/article/publish", domainAuth.RequiresPermissions("article:read && article:write", casbin.WithLogic(casbin.CUSTOM), casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
			c.String(200, "Publishing article in tenant2")
		})
	}

	// Global routes - only super admin can access
	h.GET("/global/system", domainAuth.RequiresPermissions("system:manage", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
		c.String(200, "Global system management")
	})

	// Cross-tenant user info (alice has different roles in different tenants)
	h.GET("/user/info", func(ctx context.Context, c *app.RequestContext) {
		session := sessions.Default(c)
		user := session.Get("user")
		tenant := session.Get("tenant")

		if user == nil || tenant == nil {
			c.String(401, "Not authenticated")
			return
		}

		// Get user roles in current tenant
		subject, domain := subjectAndDomainFromSession(ctx, c)
		if subject == "" {
			c.String(401, "Invalid session")
			return
		}

		// This would normally come from your auth middleware
		roles := domainAuth.Enforcer().GetRolesForUserInDomain(subject, domain)
		c.JSON(200, map[string]interface{}{
			"user":   user,
			"tenant": tenant,
			"roles":  roles,
		})
	})

	log.Println("Multi-tenant Casbin server starting on :8080")
	h.Spin()
}

// subjectAndDomainFromSession extracts both user and tenant from session
func subjectAndDomainFromSession(ctx context.Context, c *app.RequestContext) (string, string) {
	session := sessions.Default(c)

	user, userOk := session.Get("user").(string)
	tenant, tenantOk := session.Get("tenant").(string)

	// Security: Only allow tenant information from authenticated session
	// Do not infer tenant from URL to prevent tenant privilege escalation
	if !userOk || !tenantOk {
		return "", ""
	}

	if user == "" || tenant == "" {
		return "", ""
	}

	// Validate domain and subject names for security
	if err := casbin.ValidateDomainName(tenant); err != nil {
		log.Printf("Invalid domain name %s: %v", tenant, err)
		return "", ""
	}

	if err := casbin.ValidateSubjectName(user); err != nil {
		log.Printf("Invalid subject name %s: %v", user, err)
		return "", ""
	}

	return user, tenant
}
