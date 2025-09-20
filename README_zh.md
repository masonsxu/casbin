[English](README.md)

# Casbin (这是一个社区驱动的项目)

Casbin 是一个支持 ACL、RBAC、ABAC 等访问控制模型的授权库。

这个仓库的灵感来自于 [fiber-casbin](https://github.com/gofiber/contrib/tree/main/casbin) 并为 Hertz 进行了适配。

## 特性

- ✅ **多租户 RBAC 支持**: 内置基于域的访问控制支持
- ✅ **基于角色的访问控制 (RBAC)**: 支持用户角色和权限
- ✅ **灵活的授权逻辑**: 支持 AND、OR 和 CUSTOM 逻辑以进行复杂的权限检查
- ✅ **多种访问控制模型**: 通过 Casbin 支持 ACL、RBAC、ABAC
- ✅ **会话集成**: 轻松与 Hertz 会话集成以获取用户上下文
- ✅ **可配置的响应**: 自定义未经授权和禁止访问的处理器

## 安装

```shell
go get github.com/hertz-contrib/casbin
```

## 导入

```go
import "github.com/hertz-contrib/casbin"
```

## 示例

### 基本单租户用法

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

    // 使用 sessions 和 casbin。
    store := cookie.NewStore([]byte("secret"))
    h.Use(sessions.New("session", store))
    auth, err := casbin.NewCasbinMiddleware("example/basic/config/model.conf", "example/basic/config/policy.csv", subjectFromSession)
    if err != nil {
        log.Fatal(err)
    }

    h.POST("/login", func(ctx context.Context, c *app.RequestContext) {
        // 验证用户名和密码。
        // ...

        // 在会话中存储当前主题
        session := sessions.Default(c)
        session.Set("name", "alice")
        err := session.Save()
        if err != nil {
            log.Fatal(err)
        }
        c.String(200, "您已成功登录")
    })

    h.GET("/book/r", auth.RequiresPermissions("book:read", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您已成功读取书籍")
    })
    h.GET("/book/rw", auth.RequiresPermissions("book:read book:write", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您读取书籍失败")
    })
    h.GET("/book/custom/rw", auth.RequiresPermissions("book:read && book:write", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您读取书籍失败")
    })

    h.POST("/book/u", auth.RequiresRoles("user", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您已成功发布一本书")
    })
    h.POST("/book/ua", auth.RequiresRoles("user admin", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您发布书籍失败")
    })
    h.POST("/book/custom/ua", auth.RequiresRoles("user && admin", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "您发布书籍失败")
    })

    h.Spin()
}

// subjectFromSession 从会话中获取主题。
func subjectFromSession(ctx context.Context, c *app.RequestContext) string {
    // 从会话中获取主题。
    session := sessions.Default(c)
    if subject, ok := session.Get("name").(string); !ok {
        return ""
    } else {
        return subject
    }
}
```

### 多租户用法

对于多租户应用程序，请使用基于域的访问控制：

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

    // 为多租户认证使用会话
    store := cookie.NewStore([]byte("secret"))
    h.Use(sessions.New("session", store))

    // 初始化多租户 Casbin 中间件
    auth, err := casbin.NewCasbinMiddleware("example/multi-tenant/config/model_multi_tenant.conf", "example/multi-tenant/config/policy_multi_tenant.csv", nil)
    if err != nil {
        log.Fatal(err)
    }

    // 创建域感知中间件
    domainAuth, err := casbin.NewCasbinMiddlewareFromEnforcerWithDomain(auth.Enforcer(), subjectAndDomainFromSession)
    if err != nil {
        log.Fatal(err)
    }

    // 登录端点 - 在会话中设置用户和租户
    h.POST("/login", func(ctx context.Context, c *app.RequestContext) {
        user := string(c.PostForm("user"))
        tenant := string(c.PostForm("tenant"))

        // 验证用户名、密码和租户访问权限
        // ... 此处为认证逻辑 ...

        // 在会话中存储当前主题和域
        session := sessions.Default(c)
        session.Set("user", user)
        session.Set("tenant", tenant)
        err := session.Save()
        if err != nil {
            log.Printf("保存会话失败: %v", err)
            c.String(500, "会话保存失败")
            return
        }
        c.String(200, "用户 %s 在租户 %s 中登录成功", user, tenant)
    })

    // Tenant1 路由 - 书籍管理
    tenant1 := h.Group("/tenant1")
    {
        // 管理员可以在 tenant1 中读/写/删除书籍
        tenant1.GET("/book/read", domainAuth.RequiresPermissions("book:read", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "在 tenant1 中读取书籍")
        })

        tenant1.POST("/book/write", domainAuth.RequiresPermissions("book:write", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "在 tenant1 中写入书籍")
        })

        // 基于角色的访问
        tenant1.POST("/admin-action", domainAuth.RequiresRoles("admin", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "在 tenant1 中的管理员操作")
        })
    }

    // Tenant2 路由 - 文章管理
    tenant2 := h.Group("/tenant2")
    {
        // 不同的资源（文章）具有不同的角色
        tenant2.GET("/article/read", domainAuth.RequiresPermissions("article:read", casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "在 tenant2 中读取文章")
        })

        // 复杂的权限逻辑
        tenant2.POST("/article/publish", domainAuth.RequiresPermissions("article:read && article:write", casbin.WithLogic(casbin.CUSTOM), casbin.WithEnableDomains(true)), func(ctx context.Context, c *app.RequestContext) {
            c.String(200, "在 tenant2 中发布文章")
        })
    }

    h.Spin()
}

// subjectAndDomainFromSession 从会话中提取用户和租户
func subjectAndDomainFromSession(ctx context.Context, c *app.RequestContext) (string, string) {
    session := sessions.Default(c)

    user, userOk := session.Get("user").(string)
    tenant, tenantOk := session.Get("tenant").(string)

    if !userOk || !tenantOk {
        // 也尝试从 URL 路径中提取租户
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

### 多租户模型配置

创建一个支持域的模型文件 (`model_multi_tenant.conf`)：

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

### 多租户策略配置

创建一个包含特定域权限的策略文件 (`policy_multi_tenant.csv`)：

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

## 选项

| 选项 | 默认值 | 描述 |
| --- | --- | --- |
| Logic | AND | Logic 是在指定多个权限或角色时用于权限检查的逻辑操作 (AND/OR/CUSTOM)。 |
| PermissionParser | PermissionParserWithSeparator(":") | PermissionParserFunc 用于解析权限以通常提取对象和操作。 |
| PermissionParserSeparator | * | PermissionParserSeparator 用于解析权限以通常提取对象和操作。 |
| EnableDomains | false | EnableDomains 为具有域的 RBAC 启用多租户域支持。 |
| Unauthorized | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusUnauthorized) } | Unauthorized 定义了未经授权响应的响应体。 |
| Forbidden | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusForbidden) } | Forbidden 定义了禁止访问响应的响应体。 |

**注意**：当在 `WithLogic` 中使用 `CUSTOM` 时，禁止使用 `WithPermissionParser` 选项。

## 多租户特性

此实现提供了全面的多租户 RBAC 支持：

### 主要特性

1. **基于域的访问控制**: 用户可以在不同的租户/域中拥有不同的角色和权限
2. **租户隔离**: 租户之间的权限完全分离
3. **灵活的角色分配**: 同一个用户可以在不同的租户中拥有不同的角色
4. **跨租户管理**: 支持具有系统范围访问权限的全局管理员
5. **向后兼容**: 现有的单租户配置继续有效

### 使用场景

- **SaaS 应用程序**: 具有隔离权限的不同组织
- **多组织系统**: 拥有不同部门/子公司的公司
- **云平台**: 具有独立资源访问权限的多个客户端
- **企业应用程序**: 具有不同访问级别的不同业务单元

### 从单租户迁移

要从单租户迁移到多租户：

1. **更新模型**: 使用 `model_multi_tenant.conf` 而不是 `model.conf`
2. **更新策略**: 将域列添加到您现有的策略中
3. **实现域查找**: 创建 `DomainLookupHandler` 函数
4. **使用域中间件**: 切换到 `NewCasbinMiddlewareFromEnforcerWithDomain`
5. **启用域选项**: 将 `WithEnableDomains(true)` 添加到您的中间件选项中
