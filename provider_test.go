package autodns

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestProvider_Integration(t *testing.T) {
	// Get credentials from environment variables
	username := os.Getenv("AUTODNS_USERNAME")
	password := os.Getenv("AUTODNS_PASSWORD")
	contextValue := os.Getenv("AUTODNS_CONTEXT")
	zone := os.Getenv("AUTODNS_ZONE")

	// Skip test if credentials are not provided
	if username == "" || password == "" || zone == "" {
		t.Skip("AUTODNS_USERNAME, AUTODNS_PASSWORD, and AUTODNS_ZONE environment variables required")
	}

	// Use default context if not provided
	if contextValue == "" {
		contextValue = "4" // Default to live environment
	}

	provider := &Provider{
		Username: username,
		Password: password,
		Context:  contextValue,
	}

	ctx := context.Background()

	// Test 1: Get existing records
	t.Run("GetRecords", func(t *testing.T) {
		records, err := provider.GetRecords(ctx, zone)
		if err != nil {
			t.Errorf("GetRecords failed: %v", err)
			return
		}
		t.Logf("Found %d existing records", len(records))
		for _, record := range records {
			// Use type assertion to get specific record types
			switch r := record.(type) {
			case libdns.Address:
				t.Logf("- A %s %s", r.Name, r.IP.String())
			case libdns.TXT:
				t.Logf("- TXT %s %s", r.Name, r.Text)
			case libdns.CNAME:
				t.Logf("- CNAME %s %s", r.Name, r.Target)
			case libdns.MX:
				t.Logf("- MX %s %s (pref: %d)", r.Name, r.Target, r.Preference)
			case libdns.NS:
				t.Logf("- NS %s %s", r.Name, r.Target)
			case libdns.SRV:
				t.Logf("- SRV %s %s:%d (priority: %d, weight: %d)", r.Name, r.Target, r.Port, r.Priority, r.Weight)
			case libdns.CAA:
				t.Logf("- CAA %s %s:%s (flags: %d)", r.Name, r.Tag, r.Value, r.Flags)
			default:
				t.Logf("- Unknown record type: %T", record)
			}
		}
	})

	// Test 2: Add a test TXT record
	t.Run("AppendRecords", func(t *testing.T) {
		testRecord := libdns.TXT{
			Name: "test-integration",
			Text: "This is a test record from libdns-autodns",
			TTL:  300 * time.Second,
		}

		addedRecords, err := provider.AppendRecords(ctx, zone, []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("AppendRecords failed: %v", err)
			return
		}
		t.Logf("Added %d records", len(addedRecords))
	})

	// Test 3: Add a test A record
	t.Run("AppendARecord", func(t *testing.T) {
		testRecord := libdns.Address{
			Name: "test-a",
			IP:   netip.MustParseAddr("192.168.1.100"),
			TTL:  300 * time.Second,
		}

		addedRecords, err := provider.AppendRecords(ctx, zone, []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("Append A record failed: %v", err)
			return
		}
		t.Logf("Added %d A records", len(addedRecords))
	})

	// Test 4: Add a test CNAME record
	t.Run("AppendCNAMERecord", func(t *testing.T) {
		testRecord := libdns.CNAME{
			Name:   "test-cname",
			Target: "example.com",
			TTL:    300 * time.Second,
		}

		addedRecords, err := provider.AppendRecords(ctx, zone, []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("Append CNAME record failed: %v", err)
			return
		}
		t.Logf("Added %d CNAME records", len(addedRecords))
	})

	// Test 5: Delete the test records
	t.Run("DeleteRecords", func(t *testing.T) {
		// Create the same records to delete
		txtRecord := libdns.TXT{
			Name: "test-integration",
			Text: "This is a test record from libdns-autodns",
			TTL:  300 * time.Second,
		}

		aRecord := libdns.Address{
			Name: "test-a",
			IP:   netip.MustParseAddr("192.168.1.100"),
			TTL:  300 * time.Second,
		}

		cnameRecord := libdns.CNAME{
			Name:   "test-cname",
			Target: "example.com",
			TTL:    300 * time.Second,
		}

		deletedRecords, err := provider.DeleteRecords(ctx, zone, []libdns.Record{txtRecord, aRecord, cnameRecord})
		if err != nil {
			t.Errorf("DeleteRecords failed: %v", err)
			return
		}
		t.Logf("Deleted %d records", len(deletedRecords))
	})
}

func TestProvider_SetRecords(t *testing.T) {
	// Get credentials from environment variables
	username := os.Getenv("AUTODNS_USERNAME")
	password := os.Getenv("AUTODNS_PASSWORD")
	contextValue := os.Getenv("AUTODNS_CONTEXT")
	zone := os.Getenv("AUTODNS_ZONE")

	// Skip test if credentials are not provided
	if username == "" || password == "" || zone == "" {
		t.Skip("AUTODNS_USERNAME, AUTODNS_PASSWORD, and AUTODNS_ZONE environment variables required")
	}

	provider := &Provider{
		Username: username,
		Password: password,
		Context:  contextValue,
	}

	ctx := context.Background()

	t.Run("SetRecords", func(t *testing.T) {
		// First, create a test record to modify
		originalRecord := libdns.TXT{
			Name: "test-set-modify",
			Text: "Original text value",
			TTL:  300 * time.Second,
		}

		// Add the original record
		_, err := provider.AppendRecords(ctx, zone, []libdns.Record{originalRecord})
		if err != nil {
			t.Errorf("Failed to create original record: %v", err)
			return
		}
		t.Logf("Created original record: %s", originalRecord.Text)

		// Now modify the record using SetRecords
		modifiedRecord := libdns.TXT{
			Name: "test-set-modify",
			Text: "Modified text value",
			TTL:  900 * time.Second, // Change TTL to 15 minutes to test TTL modification
		}

		// Set the modified record (this should replace the original)
		setRecords, err := provider.SetRecords(ctx, zone, []libdns.Record{modifiedRecord})
		if err != nil {
			t.Errorf("SetRecords failed: %v", err)
			return
		}
		t.Logf("Set %d records", len(setRecords))

		// Verify the record was modified
		allRecords, err := provider.GetRecords(ctx, zone)
		if err != nil {
			t.Errorf("GetRecords after SetRecords failed: %v", err)
			return
		}

		// Find the modified record
		var foundRecord *libdns.TXT
		for _, record := range allRecords {
			if txt, ok := record.(libdns.TXT); ok {
				if txt.Name == "test-set-modify" {
					foundRecord = &txt
					break
				}
			}
		}

		if foundRecord == nil {
			t.Error("Modified record not found")
			return
		}

		// Check that the record was actually modified
		if foundRecord.Text != "Modified text value" {
			t.Errorf("Expected text 'Modified text value', got '%s'", foundRecord.Text)
		}
		if foundRecord.TTL != 900*time.Second {
			t.Errorf("Expected TTL 900s, got %v", foundRecord.TTL)
		}

		t.Logf("Successfully modified record: %s (TTL: %v)", foundRecord.Text, foundRecord.TTL)

		// Clean up: delete the test record
		deletedRecords, err := provider.DeleteRecords(ctx, zone, []libdns.Record{*foundRecord})
		if err != nil {
			t.Errorf("Failed to clean up test record: %v", err)
		} else {
			t.Logf("Cleaned up %d test records", len(deletedRecords))
		}
	})
}

func TestProvider_ErrorHandling(t *testing.T) {
	// Test with invalid credentials
	provider := &Provider{
		Username: "invalid",
		Password: "invalid",
		Context:  "4",
	}

	ctx := context.Background()

	t.Run("InvalidCredentials", func(t *testing.T) {
		_, err := provider.GetRecords(ctx, "example.com")
		if err == nil {
			t.Error("Expected error with invalid credentials, got nil")
		} else {
			t.Logf("Expected error with invalid credentials: %v", err)
		}
	})
}

func TestProvider_DefaultValues(t *testing.T) {
	provider := &Provider{
		Username: "test",
		Password: "test",
		// Context and Endpoint are empty to test defaults
	}

	// Test that defaults are set
	err := provider.ensureInitialized()
	if err != nil {
		t.Errorf("ensureInitialized failed: %v", err)
	}

	if provider.Context == "" {
		t.Error("Expected Context to be set to default value")
	}
	if provider.Endpoint == "" {
		t.Error("Expected Endpoint to be set to default value")
	}

	t.Logf("Default Context: %s", provider.Context)
	t.Logf("Default Endpoint: %s", provider.Endpoint)
}

func TestServiceBindingSupport(t *testing.T) {
	// Test ServiceBinding to ResourceRecord conversion
	zone := "example.com"

	// Create a ServiceBinding record
	svcBinding := libdns.ServiceBinding{
		Name:     "test",
		TTL:      300 * time.Second,
		Scheme:   "https",
		Priority: 1,
		Target:   "example.net",
		Params: libdns.SvcParams{
			"alpn": []string{"h2", "h3"},
		},
	}

	// Convert to ResourceRecord
	rr := libdnsRecordToResourceRecord(svcBinding, zone)

	// Verify the conversion
	if rr.Type != "HTTPS" {
		t.Errorf("Expected type HTTPS, got %s", rr.Type)
	}
	if rr.Name != "test.example.com" {
		t.Errorf("Expected name test.example.com, got %s", rr.Name)
	}
	if !strings.Contains(rr.Value, "1 example.net") {
		t.Errorf("Expected value to contain '1 example.net', got %s", rr.Value)
	}
	if !strings.Contains(rr.Value, "alpn=h2") {
		t.Errorf("Expected value to contain 'alpn=h2', got %s", rr.Value)
	}
}
