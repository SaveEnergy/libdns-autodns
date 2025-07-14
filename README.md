# AutoDNS for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/autodns.svg)](https://pkg.go.dev/github.com/saveenergy/libdns-autodns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for AutoDNS (InterNetX), allowing you to manage DNS records programmatically.

## Features

- ✅ **Full libdns interface support** - Get, Append, Set, and Delete records
- ✅ **AutoDNS API integration** - Uses the official AutoDNS JSON API
- ✅ **Zone management** - Automatic zone creation and management
- ✅ **Record type support** - A, AAAA, CNAME, MX, NS, SRV, TXT, CAA records
- ✅ **Authentication** - Basic authentication with username/password
- ✅ **Context support** - Demo (1) and Live (4) environment support
- ✅ **Caching** - Zone data caching for improved performance
- ✅ **Error handling** - Comprehensive error handling and reporting

## Installation

```bash
go get github.com/libdns/autodns
```

## Configuration

The provider requires the following configuration:

```go
provider := &autodns.Provider{
    Username: "your-username",     // AutoDNS username
    Password: "your-password",     // AutoDNS password
    Context:  "",                 // Optional: "1" for demo, "4" for live (default)
    Endpoint: "",                  // Optional: API endpoint (defaults to https://api.autodns.com/v1)
}
```

### Environment Variables

You can configure the provider using environment variables:

**Option 1: Export variables directly**
```bash
export AUTODNS_USERNAME="your-username"
export AUTODNS_PASSWORD="your-password"
export AUTODNS_CONTEXT="4"  # Optional
export AUTODNS_ENDPOINT=""  # Optional
```

**Option 2: Use a .env file**
1. Copy the example file: `cp env.example .env`
2. Edit `.env` with your credentials:
```bash
AUTODNS_USERNAME=your-username
AUTODNS_PASSWORD=your-password
AUTODNS_CONTEXT=4
AUTODNS_ZONE=your-domain.com
```
3. Load the variables (if your shell doesn't auto-load .env):
```bash
source .env
# or
set -a; source .env; set +a
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "log"

    "github.com/libdns/autodns"
    "github.com/libdns/libdns"
)

func main() {
    provider := &autodns.Provider{
        Username: "your-username",
        Password: "your-password",
        Context:  "", // Live environment
    }

    ctx := context.Background()
    zone := "example.com"

    // Get all records
    records, err := provider.GetRecords(ctx, zone)
    if err != nil {
        log.Fatal(err)
    }

    // Add a new A record
    newRecord := libdns.Record{
        Type:  "A",
        Name:  "www",
        Value: "192.168.1.1",
        TTL:   300 * time.Second,
    }

    addedRecords, err := provider.AppendRecords(ctx, zone, []libdns.Record{newRecord})
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Added %d records", len(addedRecords))
}
```

### Using with Caddy

Add this to your Caddyfile:

```
example.com {
    tls {
        dns autodns {
            username your-username
            password your-password
        }
    }
}
```



## Supported Record Types

The provider supports the following DNS record types:

- **A** - IPv4 address records
- **AAAA** - IPv6 address records
- **CNAME** - Canonical name records
- **MX** - Mail exchange records
- **NS** - Name server records
- **SRV** - Service records
- **TXT** - Text records
- **CAA** - Certification Authority Authorization records

## API Endpoints

The provider uses the following AutoDNS API endpoints:

- `GET /zone/{name}` - Get zone information
- `POST /zone` - Create new zone
- `PATCH /zone/{name}` - Update zone records

## Error Handling

The provider includes comprehensive error handling:

- **HTTP errors** - Proper handling of 4xx and 5xx status codes
- **API errors** - AutoDNS-specific error messages
- **Validation errors** - Record type and value validation
- **Network errors** - Timeout and connection error handling

## Authentication

The provider uses Basic Authentication with your AutoDNS credentials. Make sure your account has the necessary permissions to manage DNS zones and records.

## Context Support

AutoDNS supports different contexts:

- **Context "1"** - Demo environment for testing (requires registered AutoDNS account)
- **Context "4"** - Live environment for production (default)

## Zone Management

The provider automatically handles zone management:

- **Zone creation** - Automatically creates zones if they don't exist
- **SOA configuration** - Sets up proper SOA records for new zones
- **Zone caching** - Caches zone data for improved performance
- **Cache invalidation** - Automatically refreshes cache on updates

## Rate Limiting

The provider includes built-in rate limiting considerations:

- **Request timeouts** - 30-second timeout for API requests
- **Connection pooling** - Reuses HTTP connections
- **Error retries** - Handles temporary network issues

## Development

### Building

```bash
go build .
```

### Testing

The provider includes comprehensive integration tests. To run the tests, you need:

1. **Set environment variables** with your AutoDNS credentials:

**Option A: Export directly**
```bash
export AUTODNS_USERNAME="your-username"
export AUTODNS_PASSWORD="your-password"
export AUTODNS_CONTEXT="4"  # Optional, defaults to "4"
export AUTODNS_ZONE="your-domain.com"  # Domain you control
```

**Option B: Use .env file**
```bash
# Copy example file
cp env.example .env

# Edit .env with your credentials
# AUTODNS_USERNAME=your-username
# AUTODNS_PASSWORD=your-password
# AUTODNS_CONTEXT=4
# AUTODNS_ZONE=your-domain.com

# Load variables
source .env
```

2. **Run the tests**:
```bash
go test -v
```

**Test coverage:**
- ✅ GetRecords - Retrieves existing DNS records
- ✅ AppendRecords - Adds new TXT and A records
- ✅ SetRecords - Replaces all records in a zone
- ✅ DeleteRecords - Removes specific records
- ✅ Error handling - Tests with invalid credentials
- ✅ Default values - Tests provider configuration

**Note:** Tests require a registered AutoDNS account and a domain you control. The tests will create and delete actual DNS records.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions:

1. Check the [AutoDNS API documentation](https://github.com/InterNetX/domainrobot-api)
2. Review the [libdns documentation](https://github.com/libdns/libdns)
3. Open an issue on this repository

## Changelog

### v1.0.0
- Initial release
- Full libdns interface implementation
- AutoDNS API integration
- Zone management support
- Comprehensive error handling
