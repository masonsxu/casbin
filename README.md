[简体中文](README_zh.md)

# Casbin (This is a community driven project)

Casbin is an authorization library that supports access control models like ACL, RBAC, ABAC.

This repo inspired by [fiber-casbin](https://github.com/gofiber/contrib/tree/main/casbin) and adapted to Hertz.

## Features

- ✅ **Multi-tenant RBAC Support**: Built-in support for domain-based access control
- ✅ **Role-based Access Control (RBAC)**: Support for user roles and permissions
- ✅ **Flexible Authorization Logic**: AND, OR, and CUSTOM logic for complex permission checks
- ✅ **Multiple Access Control Models**: Support for ACL, RBAC, ABAC via Casbin
- ✅ **Session Integration**: Easy integration with Hertz sessions for user context
- ✅ **Configurable Responses**: Custom unauthorized and forbidden handlers

## Install

``` shell
go get github.com/hertz-contrib/casbin
```

## Import

```go
import "github.com/hertz-contrib/casbin"
```

## Examples

### Basic Single-Tenant Usage

```go
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

    // Using sessions and casbin.
    store := cookie.NewStore([]byte("secret"))
    h.Use(sessions.New("session", store))
    auth, err := casbin.NewCasbinMiddleware("example/basic/config/model.conf", "example/basic/config/policy.csv", subjectFromSession)
    if err != nil {
        log.Fatal(err)
    }

    h.POST("/login", func(ctx context.Context, c *app.RequestContext) {
        // Verify username and password.
        // ...

        // Store current subject in session
        session := sessions.Default(c)
        session.Set("name", "alice")
        err := session.Save()
        if err != nil {
            log.Fatal(err)
        }
        c.String(200, "you login successfully")
    })

    h.GET("/book/r", auth.RequiresPermissions("book:read", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book successfully")
    })
    h.GET("/book/rw", auth.RequiresPermissions("book:read book:write", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book failed")
    })
    h.GET("/book/custom/rw", auth.RequiresPermissions("book:read && book:write", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book failed")
    })

    h.POST("/book/u", auth.RequiresRoles("user", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book successfully")
    })
    h.POST("/book/ua", auth.RequiresRoles("user admin", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book failed")
    })
    h.POST("/book/custom/ua", auth.RequiresRoles("user && admin", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book failed")
    })

    h.Spin()
}

// subjectFromSession get subject from session.
func subjectFromSession(ctx context.Context, c *app.RequestContext) string {
    // Get subject from session.
    session := sessions.Default(c)
    if subject, ok := session.Get("name").(string); !ok {
        return ""
    } else {
        return subject
    }
}
```

### Multi-Tenant Usage

For multi-tenant applications, use domain-based access control:

```go
package main

import (
    "context"
    "log"
    "strings"

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
    auth, err := casbin.NewCasbinMiddleware("example/multi-tenant/config/model_multi_tenant.conf", "example/multi-tenant/config/policy_multi_tenant.csv", nil)
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

        // Complex permission logic
        tenant2.POST("/article/publish", domainAuth.RequiresPermissions("article:read && article:write", casbin.WithLogic(casbin.CUSTOM), casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "Publishing article in tenant2")
        })
    }

    h.Spin()
}

// subjectAndDomainFromSession extracts both user and tenant from session
func subjectAndDomainFromSession(ctx context.Context, c *app.RequestContext) (string, string) {
    session := sessions.Default(c)

    user, userOk := session.Get("user").(string)
    tenant, tenantOk := session.Get("tenant").(string)

    if !userOk || !tenantOk {
        // Also try to extract tenant from URL path
        path := string(c.Path())
        if strings.HasPrefix(path, "/tenant1") {
            tenant = "tenant1"
        } else if strings.HasPrefix(path, "/tenant2") {
            tenant = "tenant2"
        } else if strings.HasPrefix(path, "/global") {
            tenant = "global"
        }
    }

    if user == "" || tenant == "" {
        return "", ""
    }

    return user, tenant
}
```

### Multi-Tenant Model Configuration

Create a model file (`model_multi_tenant.conf`) that supports domains:

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

### Multi-Tenant Policy Configuration

Create a policy file (`policy_multi_tenant.csv`) with domain-specific permissions:

```csv
p, admin, tenant1, book, read
p, admin, tenant1, book, write
p, admin, tenant1, book, delete
p, user, tenant1, book, read
p, guest, tenant1, book, read

p, admin, tenant2, article, read
p, admin, tenant2, article, write
p, editor, tenant2, article, write
p, reader, tenant2, article, read

p, super_admin, global, system, manage

g, alice, admin, tenant1
g, alice, reader, tenant2
g, bob, user, tenant1
g, charlie, admin, tenant2
g, david, editor, tenant2
g, eve, guest, tenant1
g, frank, super_admin, global
```

## Options

| Option                    | Default                                                      | Description                                                  |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Logic                     | AND                                                          | Logic is the logical operation (AND/OR/CUSTOM) used in permission checks in case multiple permissions or roles are specified. |
| PermissionParser          | PermissionParserWithSeparator(":")                           | PermissionParserFunc is used for parsing the permission to extract object and action usually. |
| PermissionParserSeparator | *                                                            | PermissionParserSeparator is used for parsing the permission to extract object and action usually. |
| EnableDomains             | false                                                        | EnableDomains enables multi-tenant domain support for RBAC with domains. |
| Unauthorized              | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusUnauthorized) }  | Unauthorized defines the response body for unauthorized responses. |
| Forbidden                 | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusForbidden) } | Forbidden defines the response body for forbidden responses. |

**Attention**: when use `CUSTOM` in `WithLogic`, use `WithPermissionParser` Option is forbidden.

## Multi-Tenant Features

This implementation provides comprehensive multi-tenant RBAC support:

### Key Features

1. **Domain-Based Access Control**: Users can have different roles and permissions in different tenants/domains
2. **Tenant Isolation**: Complete separation of permissions between tenants
3. **Flexible Role Assignment**: Same user can have different roles in different tenants
4. **Cross-Tenant Administration**: Support for global administrators with system-wide access
5. **Backward Compatibility**: Existing single-tenant configurations continue to work

### Use Cases

- **SaaS Applications**: Different organizations with isolated permissions
- **Multi-Organization Systems**: Companies with different departments/subsidiaries
- **Cloud Platforms**: Multiple clients with separate resource access
- **Enterprise Applications**: Different business units with varying access levels

### Migration from Single-Tenant

To migrate from single-tenant to multi-tenant:

1. **Update Model**: Use `model_multi_tenant.conf` instead of `model.conf`
2. **Update Policies**: Add domain column to your existing policies
3. **Implement Domain Lookup**: Create `DomainLookupHandler` function
4. **Use Domain Middleware**: Switch to `NewCasbinMiddlewareFromEnforcerWithDomain`
5. **Enable Domain Options**: Add `WithEnableDomains(true)` to your middleware options
