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

// Zone represents an AutoDNS zone according to the official API schema
type Zone struct {
	Created               time.Time        `json:"created,omitempty"`
	Updated               time.Time        `json:"updated,omitempty"`
	Origin                string           `json:"origin,omitempty"`
	IDN                   string           `json:"idn,omitempty"`
	SOA                   *SOA             `json:"soa,omitempty"`
	DNSSEC                bool             `json:"dnssec,omitempty"`
	NameServerGroup       string           `json:"nameServerGroup,omitempty"`
	AllowTransfer         bool             `json:"allowTransfer,omitempty"`
	Owner                 *BasicUser       `json:"owner,omitempty"`
	Updater               *BasicUser       `json:"updater,omitempty"`
	LogID                 int64            `json:"logId,omitempty"`
	Comment               string           `json:"comment,omitempty"`
	DomainSafe            bool             `json:"domainsafe,omitempty"`
	Source                string           `json:"source,omitempty"`
	SourceVirtualHostname string           `json:"sourceVirtualHostname,omitempty"`
	PurgeDate             time.Time        `json:"purgeDate,omitempty"`
	PurgeType             string           `json:"purgeType,omitempty"`
	Date                  time.Time        `json:"date,omitempty"`
	External              bool             `json:"external,omitempty"`
	InUse                 bool             `json:"inUse,omitempty"`
	NameServers           []NameServer     `json:"nameServers,omitempty"`
	Main                  *MainIp          `json:"main,omitempty"`
	WWWInclude            bool             `json:"wwwInclude,omitempty"`
	VirtualNameServer     string           `json:"virtualNameServer,omitempty"`
	FreeText              []string         `json:"freeText,omitempty"`
	Action                string           `json:"action,omitempty"`
	Grants                []string         `json:"grants,omitempty"`
	ResourceRecords       []ResourceRecord `json:"resourceRecords,omitempty"`
	ROID                  int32            `json:"roid,omitempty"`
}

// SOA represents the SOA record structure
type SOA struct {
	Refresh int64  `json:"refresh,omitempty"`
	Retry   int64  `json:"retry,omitempty"`
	Expire  int64  `json:"expire,omitempty"`
	TTL     int64  `json:"ttl,omitempty"`
	Email   string `json:"email,omitempty"`
}

// BasicUser represents a basic user structure
type BasicUser struct {
	Context         int32     `json:"context,omitempty"`
	PasswordChanged time.Time `json:"passwordChanged,omitempty"`
	PasswordExpires time.Time `json:"passwordExpires,omitempty"`
	User            string    `json:"user,omitempty"`
	PasswordExpired bool      `json:"passwordExpired,omitempty"`
}

// NameServer represents a nameserver structure
type NameServer struct {
	Name        string   `json:"name,omitempty"`
	TTL         int64    `json:"ttl,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

// MainIp represents the main IP address structure
type MainIp struct {
	Address string `json:"address,omitempty"`
	TTL     int64  `json:"ttl,omitempty"`
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
		rr = ResourceRecord{
			Name:  libdns.AbsoluteName(r.Name, zone),
			TTL:   int64(r.TTL / time.Second),
			Type:  "A",
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
	default:
		// Fallback for unknown record types
		rr = ResourceRecord{
			Name:  "unknown",
			TTL:   0,
			Type:  "UNKNOWN",
			Value: "unknown",
		}
	}

	return rr
}

// Standard AutoDNS API response structure
type JsonResponse struct {
	Status ResponseStatus  `json:"status,omitempty"`
	STID   string          `json:"stid,omitempty"`
	Object ResponseObject  `json:"object,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// ResponseStatus represents the status of an API response
type ResponseStatus struct {
	Code string `json:"code,omitempty"`
	Text string `json:"text,omitempty"`
	Type string `json:"type,omitempty"`
}

// ResponseObject represents an object in the API response
type ResponseObject struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// JsonResponseDataZone represents a zone response
type JsonResponseDataZone struct {
	Zone Zone `json:"zone,omitempty"`
}

// JsonResponseDataListJsonResponseDataZone represents a list of zones response
type JsonResponseDataListJsonResponseDataZone struct {
	Zones []Zone `json:"zones,omitempty"`
}

// ZonePatchRequest represents a zone patch request
type ZonePatchRequest struct {
	Zone Zone `json:"zone,omitempty"`
}

// ZonePostRequest represents a zone creation request
type ZonePostRequest struct {
	Zone Zone `json:"zone,omitempty"`
}

// ZoneDeleteRequest represents a zone deletion request
type ZoneDeleteRequest struct {
	Zone Zone `json:"zone,omitempty"`
}

// BulkZonePostRequest represents a bulk zone creation request
type BulkZonePostRequest struct {
	Zones []Zone `json:"zones,omitempty"`
}

// BulkZonePatchRequest represents a bulk zone update request
type BulkZonePatchRequest struct {
	Zones []Zone `json:"zones,omitempty"`
}

// BulkZoneDeleteRequest represents a bulk zone deletion request
type BulkZoneDeleteRequest struct {
	Zones []Zone `json:"zones,omitempty"`
}
