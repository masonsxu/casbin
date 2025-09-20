# Examples

This directory contains examples demonstrating different usage patterns of the Casbin middleware.

## Directory Structure

```
example/
├── basic/               # Single-tenant RBAC examples
│   ├── main.go         # Basic usage example
│   └── config/         # Configuration files for basic examples
│       ├── model.conf  # Casbin model for basic RBAC
│       └── *.csv       # Policy files
└── multi-tenant/       # Multi-tenant RBAC examples
    ├── main.go         # Multi-tenant usage example
    └── config/         # Configuration files for multi-tenant
        ├── model_multi_tenant.conf  # Domain-aware model
        └── policy_multi_tenant.csv  # Multi-tenant policies
```

## Running the Examples

### Basic Example
```bash
cd example/basic
go run main.go
```

### Multi-tenant Example
```bash
cd example/multi-tenant
go run main.go
```

## Configuration Files

- **basic/config/**: Contains traditional single-tenant configurations
- **multi-tenant/config/**: Contains domain-aware configurations for multi-tenant scenarios

Each example directory contains its own complete configuration to demonstrate the respective use case.