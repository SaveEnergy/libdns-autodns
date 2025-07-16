package autodns

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// AutoDNSTime handles AutoDNS time formats like "2023-12-18T15:25:18.000+0100" and RFC3339
// It implements json.Unmarshaler
type AutoDNSTime struct {
	time.Time
}

func (t AutoDNSTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte(`null`), nil
	}
	return json.Marshal(t.Time)
}

func (t *AutoDNSTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}

	// AutoDNS uses format: "2023-12-18T15:25:18.000+0100"
	layout := "2006-01-02T15:04:05.000-0700"

	parsed, err := time.Parse(layout, s)
	if err != nil {
		return fmt.Errorf("AutoDNSTime: could not parse time %q: %v", s, err)
	}

	t.Time = parsed
	return nil
}

// Zone represents an AutoDNS zone according to the official API schema
type Zone struct {
	Created           *AutoDNSTime     `json:"created,omitempty"`
	Updated           *AutoDNSTime     `json:"updated,omitempty"`
	Origin            string           `json:"origin,omitempty"`
	SOA               *SOA             `json:"soa,omitempty"`
	NameServers       []NameServer     `json:"nameServers,omitempty"`
	WWWInclude        bool             `json:"wwwInclude,omitempty"`
	VirtualNameServer string           `json:"virtualNameServer,omitempty"`
	Action            string           `json:"action,omitempty"`
	ResourceRecords   []ResourceRecord `json:"resourceRecords,omitempty"`
	ROID              int32            `json:"roid,omitempty"`
}

// SOA represents the SOA record structure
type SOA struct {
	Refresh int64  `json:"refresh,omitempty"`
	Retry   int64  `json:"retry,omitempty"`
	Expire  int64  `json:"expire,omitempty"`
	TTL     int64  `json:"ttl,omitempty"`
	Email   string `json:"email,omitempty"`
}

// NameServer represents a nameserver structure
type NameServer struct {
	Name        string   `json:"name,omitempty"`
	TTL         int64    `json:"ttl,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

// ResourceRecord represents a DNS resource record
type ResourceRecord struct {
	Name  string `json:"name,omitempty"`
	TTL   int64  `json:"ttl,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
	Pref  int32  `json:"pref,omitempty"`
	Raw   string `json:"raw,omitempty"`
}

// Convert ResourceRecord to libdns.Record
func (r ResourceRecord) libdnsRecord(zone string) (libdns.Record, error) {
	name := libdns.RelativeName(r.Name, zone)
	ttl := time.Duration(r.TTL) * time.Second

	switch r.Type {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(r.Value)
		if err != nil {
			return libdns.Address{}, fmt.Errorf("invalid IP address %q: %v", r.Value, err)
		}
		return libdns.Address{
			Name: name,
			TTL:  ttl,
			IP:   addr,
		}, nil
	case "CAA":
		fields := strings.Fields(r.Value)
		if expectedLen := 3; len(fields) != expectedLen {
			return libdns.CAA{}, fmt.Errorf(`malformed CAA value; expected %d fields in the form 'flags tag "value"'`, expectedLen)
		}

		flags, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			return libdns.CAA{}, fmt.Errorf("invalid flags %s: %v", fields[0], err)
		}

		tag := fields[1]
		value := strings.Trim(fields[2], `"`)

		return libdns.CAA{
			Name:  name,
			TTL:   ttl,
			Flags: uint8(flags),
			Tag:   tag,
			Value: value,
		}, nil
	case "CNAME":
		return libdns.CNAME{
			Name:   name,
			TTL:    ttl,
			Target: r.Value,
		}, nil
	case "MX":
		return libdns.MX{
			Name:       name,
			TTL:        ttl,
			Preference: uint16(r.Pref),
			Target:     r.Value,
		}, nil
	case "NS":
		return libdns.NS{
			Name:   name,
			TTL:    ttl,
			Target: r.Value,
		}, nil
	case "SRV":
		fields := strings.Fields(r.Value)
		if expectedLen := 3; len(fields) != expectedLen {
			return libdns.SRV{}, fmt.Errorf("malformed SRV value; expected %d fields in the form 'priority weight port target'", expectedLen)
		}

		weight, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return libdns.SRV{}, fmt.Errorf("invalid weight %s: %v", fields[0], err)
		}
		port, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return libdns.SRV{}, fmt.Errorf("invalid port %s: %v", fields[1], err)
		}
		target := fields[2]

		parts := strings.SplitN(r.Name, ".", 3)
		if len(parts) < 2 {
			return libdns.SRV{}, fmt.Errorf("name %v does not contain enough fields; expected format: '_service._proto.name' or '_service._proto'", r.Name)
		}
		name := "@"
		if len(parts) == 3 {
			name = parts[2]
		}

		return libdns.SRV{
			Service:   strings.TrimPrefix(parts[0], "_"),
			Transport: strings.TrimPrefix(parts[1], "_"),
			Name:      name,
			TTL:       time.Duration(r.TTL) * time.Second,
			Priority:  uint16(r.Pref),
			Weight:    uint16(weight),
			Port:      uint16(port),
			Target:    target,
		}, nil
	case "TXT":
		return libdns.TXT{
			Name: name,
			TTL:  ttl,
			Text: r.Value,
		}, nil
	case "SVCB", "HTTPS":
		// Handle ServiceBinding records (SVCB/HTTPS)
		// For now, we'll treat them as generic records since parsing SvcParams is complex
		// and the AutoDNS API might not support these record types directly
		return libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: r.Type,
			Data: r.Value,
		}.Parse()
	default:
		return libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: r.Type,
			Data: r.Value,
		}.Parse()
	}
}

// Convert libdns.Record to ResourceRecord
func libdnsRecordToResourceRecord(record libdns.Record, zone string) ResourceRecord {
	var rr ResourceRecord

	switch r := record.(type) {
	case libdns.Address:
		// Determine if it's A or AAAA based on IP address type
		recordType := "A"
		if r.IP.Is6() {
			recordType = "AAAA"
		}
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  recordType,
			Value: r.IP.String(),
		}
	case libdns.CAA:
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "CAA",
			Value: fmt.Sprintf("%d %s \"%s\"", r.Flags, r.Tag, r.Value),
		}
	case libdns.CNAME:
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "CNAME",
			Value: r.Target,
		}
	case libdns.MX:
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "MX",
			Value: r.Target,
			Pref:  int32(r.Preference),
		}
	case libdns.NS:
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "NS",
			Value: r.Target,
		}
	case libdns.SRV:
		rr = ResourceRecord{
			Name:  fmt.Sprintf("_%s._%s.%s", r.Service, r.Transport, libdns.AbsoluteName(r.Name, zone)),
			TTL:   int64(r.TTL / time.Second),
			Type:  "SRV",
			Value: fmt.Sprintf("%d %d %s", r.Weight, r.Port, r.Target),
			Pref:  int32(r.Priority),
		}
	case libdns.TXT:
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "TXT",
			Value: r.Text,
		}
	case libdns.ServiceBinding:
		// Determine the record type based on the scheme
		recordType := "SVCB"
		if r.Scheme == "https" {
			recordType = "HTTPS"
		}

		// Convert ServiceBinding to a string representation
		// This is a simplified approach - in practice, you might need more complex logic
		value := fmt.Sprintf("%d %s", r.Priority, r.Target)
		if len(r.Params) > 0 {
			// Add parameters if present
			paramStrs := make([]string, 0, len(r.Params))
			for key, values := range r.Params {
				for _, value := range values {
					paramStrs = append(paramStrs, fmt.Sprintf("%s=%s", key, value))
				}
			}
			value += " " + strings.Join(paramStrs, " ")
		}

		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  recordType,
			Value: value,
		}
	case libdns.RR:
		// Handle generic RR records (like DNS-01 challenges)
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  r.Type,
			Value: r.Data,
		}
	default:
		// For unknown record types, provide better debugging information
		// This is better than creating "unknown" records
		recordName := "unknown"
		recordType := "UNKNOWN"
		recordValue := "unknown"
		recordTTL := int64(0)

		// Log the unknown record type for debugging
		fmt.Printf("Warning: Unknown record type %T - this may indicate a missing record type handler\n", record)
		fmt.Printf("Record details: %+v\n", record)

		rr = ResourceRecord{
			Name:  recordName,
			TTL:   recordTTL,
			Type:  recordType,
			Value: recordValue,
		}
	}

	return rr
}

// Standard AutoDNS API response structure
type JsonResponse struct {
	Status ResponseStatus  `json:"status,omitempty"`
	STID   string          `json:"stid,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// ResponseStatus represents the status of an API response
type ResponseStatus struct {
	Code string `json:"code,omitempty"`
	Text string `json:"text,omitempty"`
	Type string `json:"type,omitempty"`
}
