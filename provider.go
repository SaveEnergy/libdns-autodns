// Package autodns implements a DNS record management client compatible
// with the libdns interfaces for AutoDNS.
package autodns

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with AutoDNS.
type Provider struct {
	// Username for Basic Authentication (AutoDNS user)
	Username string `json:"username,omitempty"`
	// Password for Basic Authentication
	Password string `json:"password,omitempty"`
	// Context number: 1 = demo, 4 = live
	Context string `json:"context,omitempty"`
	// Endpoint overrides the default API endpoint (optional)
	Endpoint string `json:"endpoint,omitempty"`

	// Zones is a cache of the zones in the account.
	zones      map[string]Zone
	zonesMutex sync.Mutex
}

// Endpoint URL and default context for the autodns API.
const (
	defaultEndpoint string = "https://api.autodns.com/v1"
	defaultContext  string = "4"
)

// setDefaults sets default values for optional fields
func (p *Provider) setDefaults() {
	if p.Endpoint == "" {
		p.Endpoint = defaultEndpoint
	}
	if p.Context == "" {
		p.Context = defaultContext
	}
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	// Set defaults if not provided
	p.setDefaults()

	zoneData, err := p.getZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone %s: %v", zone, err)
	}

	var records []libdns.Record
	for _, rr := range zoneData.ResourceRecords {
		record, err := rr.libdnsRecord(zone)
		if err != nil {
			return nil, fmt.Errorf("failed to convert resource record %s: %v", rr.Name, err)
		}
		records = append(records, record)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Set defaults if not provided
	p.setDefaults()

	err := p.addRecords(ctx, zone, records)
	if err != nil {
		return nil, fmt.Errorf("failed to add records to zone %s: %v", zone, err)
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Set defaults if not provided
	p.setDefaults()

	err := p.setRecords(ctx, zone, records)
	if err != nil {
		return nil, fmt.Errorf("failed to set records in zone %s: %v", zone, err)
	}

	return records, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Set defaults if not provided
	p.setDefaults()

	err := p.deleteRecords(ctx, zone, records)
	if err != nil {
		return nil, fmt.Errorf("failed to delete records from zone %s: %v", zone, err)
	}

	return records, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
