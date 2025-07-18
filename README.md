# AutoDNS for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/autodns.svg)](https://pkg.go.dev/github.com/saveenergy/libdns-autodns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for AutoDNS (InterNetX), allowing you to manage DNS records programmatically.

## Features

- ✅ **Full libdns interface support** - Get, Append, Set, and Delete records
- ✅ **AutoDNS API integration** - Uses the official AutoDNS JSON API
- ✅ **Zone-level operations** - Full zone fetch and update for reliable record management
- ✅ **Record type support** - A, AAAA, CNAME, MX, NS, SRV, TXT, CAA records
- ✅ **Authentication** - Basic authentication with username/password
- ✅ **Context support** - Demo (1) and Live (4) environment support
- ✅ **Caching** - Zone data caching for improved performance
- ✅ **Error handling** - Comprehensive error handling and reporting
- ✅ **Record preservation** - Maintains existing records when adding/modifying specific ones
- ✅ **Flexible TTL support** - Handles various TTL values with API compatibility

## Installation

```bash
go get github.com/saveenergy/libdns-autodns
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
1. Create a `.env` file with your credentials:
```bash
AUTODNS_USERNAME=your-username
AUTODNS_PASSWORD=your-password
AUTODNS_CONTEXT=4
AUTODNS_ZONE=your-domain.com
```
2. Load the variables:
```bash
source .env
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "log"
    "time"
    "net/netip"

    "github.com/saveenergy/libdns-autodns"
    "github.com/libdns/libdns"
)

func main() {
    provider := &autodns.Provider{
        Username: "your-username",
        Password: "your-password",
        Context:  "4", // Live environment
    }

    ctx := context.Background()
    zone := "example.com"

    // Get all records
    records, err := provider.GetRecords(ctx, zone)
    if err != nil {
        log.Fatal(err)
    }

    // Add a new A record
    newRecord := libdns.Address{
        Name: "www",
        IP:   netip.MustParseAddr("192.168.1.1"),
        TTL:  300 * time.Second,
    }

    addedRecords, err := provider.AppendRecords(ctx, zone, []libdns.Record{newRecord})
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Added %d records", len(addedRecords))
}
```

### Advanced Example

```go
// Add a TXT record
txtRecord := libdns.TXT{
    Name: "test",
    Text: "This is a test record",
    TTL:  300 * time.Second,
}

// Add a CNAME record
cnameRecord := libdns.CNAME{
    Name:   "mail",
    Target: "mail.example.com",
    TTL:    300 * time.Second,
}

// Add multiple records
records := []libdns.Record{txtRecord, cnameRecord}
addedRecords, err := provider.AppendRecords(ctx, zone, records)

// Modify an existing record
modifiedRecord := libdns.TXT{
    Name: "test",
    Text: "Updated text value",
    TTL:  600 * time.Second,
}

setRecords, err := provider.SetRecords(ctx, zone, []libdns.Record{modifiedRecord})

// Delete specific records
deletedRecords, err := provider.DeleteRecords(ctx, zone, []libdns.Record{txtRecord})
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

- **A** - IPv4 address records (`libdns.Address`)
- **AAAA** - IPv6 address records (`libdns.Address`)
- **CNAME** - Canonical name records (`libdns.CNAME`)
- **MX** - Mail exchange records (`libdns.MX`)
- **NS** - Name server records (`libdns.NS`)
- **SRV** - Service records (`libdns.SRV`)
- **TXT** - Text records (`libdns.TXT`)
- **CAA** - Certification Authority Authorization records (`libdns.CAA`)
- **SVCB/HTTPS** - Service Binding records (`libdns.ServiceBinding`)
- **Generic records** - Support for `libdns.RR` records (TXT, A, and other supported types, e.g. DNS-01 challenges)

## API Endpoints

The provider uses the following AutoDNS API endpoints:

- `GET /zone/{name}` - Get zone information
- `PUT /zone/{name}` - Update zone records (full zone update)

## Error Handling

The provider includes comprehensive error handling:

- **HTTP errors** - Proper handling of 4xx and 5xx status codes
- **API errors** - AutoDNS-specific error messages
- **Validation errors** - Record type and value validation
- **Input validation** - Required field validation (username, password, zone name, records)
- **Network errors** - Timeout and connection error handling
- **Zone errors** - Proper handling of zone-level operations

## Authentication

The provider uses Basic Authentication with your AutoDNS credentials. Make sure your account has the necessary permissions to manage DNS zones and records.

## Context Support

AutoDNS supports different contexts:

- **Context "1"** - Demo environment for testing (requires registered AutoDNS account)
- **Context "4"** - Live environment for production (default)

## Zone Management

The provider automatically handles zone management:

- **Zone retrieval** - Fetches complete zone data for reliable operations
- **Record preservation** - Maintains existing records when adding/modifying specific ones
- **Zone caching** - Caches zone data for improved performance
- **Cache invalidation** - Automatically refreshes cache on updates
- **Full zone updates** - Sends complete zone data to ensure consistency

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
# Create .env file with your credentials
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
- ✅ AppendRecords - Adds new TXT, A, and CNAME records
- ✅ SetRecords - Modifies existing records (text and TTL)
- ✅ DeleteRecords - Removes specific records while preserving others
- ✅ Error handling - Tests with invalid credentials
- ✅ Default values - Tests provider configuration
- ✅ Input validation - Tests for required field validation
- ✅ ServiceBinding support - Tests for SVCB/HTTPS record conversion
- ✅ RR record support - Tests for TXT and A via `libdns.RR`

**Note:** Tests require a registered AutoDNS account and a domain you control. The tests will create and delete actual DNS records.

## Recent Improvements

### v1.0.9 (Current)
- ✅ **Relative name fix** - Fixed all record types to use `libdns.RelativeName` instead of `libdns.AbsoluteName`, ensuring AutoDNS receives only subdomain names (e.g., `_acme-challenge.status` instead of `_acme-challenge.status.example.com`).

### v1.0.8
- ✅ **DNS-01 challenge fix** - Fixed handling of full FQDN names in DNS-01 challenges (e.g., `_acme-challenge.config.example.com` now correctly becomes `_acme-challenge.config`).
- ✅ **RR record handling** - Improved support for `libdns.RR` records: TXT, A, and other supported types are now properly converted, especially for DNS-01 challenges (Caddy/ACME).
- ✅ **No more 'unknown' records** - The provider no longer creates 'unknown' records for supported types; TXT challenges now work as expected.
- ✅ **Test coverage** - Added tests for RR record support and DNS-01 challenge scenarios.


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

### v1.0.9
- Fixed: All record types now use `libdns.RelativeName` instead of `libdns.AbsoluteName`, ensuring AutoDNS receives only subdomain names (e.g., `_acme-challenge.status` instead of `_acme-challenge.status.example.com`).

### v1.0.8
- Fixed: DNS-01 challenge handling for full FQDN names - now correctly extracts subdomain part (e.g., `_acme-challenge.config.example.com` becomes `_acme-challenge.config`).
- Improved: Properly handle `libdns.RR` records for TXT, A, and other supported types (especially for DNS-01 challenges and Caddy/ACME).
- Fixed: No more 'unknown' records for supported types; TXT challenges now work as expected.
- Added: Unit tests for RR record support and DNS-01 challenge scenarios.

### v1.0.7
- Improved: Properly handle libdns.RR records for TXT, A, and other supported types (especially for DNS-01 challenges and Caddy/ACME).
- Fixed: No more 'unknown' records for supported types; TXT challenges now work as expected.
- Added: Unit tests for RR record support (TXT and A).

### v1.0.6
- Added: Comprehensive input validation for required fields (username, password, zone name, records) with clear error messages.
- Added: Full support for ServiceBinding (SVCB/HTTPS) records with proper conversion between libdns.ServiceBinding and AutoDNS format.
- Added: Unit tests for validation logic and ServiceBinding record conversion.
- Improved: Error handling and input validation throughout the codebase for better reliability.
- Optimized: Simplified AutoDNSTime parsing to use the specific AutoDNS format (2023-12-18T15:25:18.000+0100), removing unnecessary fallback formats for better performance and reliability.

### v1.0.5
- Fixed: Added support for `libdns.RR` generic records, resolving DNS-01 challenge issues where Caddy creates generic TXT records that were previously treated as unknown.
- Fixed: Completely omit timestamp fields (Created and Updated) from API requests by using pointer types and nil values, ensuring clean request bodies without unnecessary read-only fields.
- Fixed: Correctly distinguish between A and AAAA records when converting from libdns.Address, preventing misclassification and 'unknown' records.
- Added: Support for ServiceBinding (SVCB/HTTPS) records, so these are no longer treated as unknown.
- Improved: The default case for unknown record types now logs a warning and avoids creating 'unknown' records unless truly necessary, aiding debugging and future extensibility.
- Added: Unit test to verify ServiceBinding record conversion.

### v1.0.2
- Code cleanup: Removed unused types and fields from models
- Improved maintainability with streamlined codebase
- Enhanced documentation with cleaner examples

### v1.0.1
- Downgraded to Go 1.24 for better compatibility

### v1.0.0
- Initial release with full libdns interface implementation
- AutoDNS API integration with zone-level operations
- Comprehensive record type support (A, AAAA, CNAME, MX, NS, SRV, TXT, CAA)
- Record preservation and proper SetRecords functionality
- Enhanced error handling and validation
- Complete test coverage for all libdns interfaces
