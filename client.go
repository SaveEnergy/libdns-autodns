package autodns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/libdns/libdns"
)

// getZone retrieves a zone from the AutoDNS API
func (p *Provider) getZone(ctx context.Context, zoneName string) (Zone, error) {
	p.zonesMutex.Lock()
	defer p.zonesMutex.Unlock()

	// Check cache first
	if p.zones == nil {
		p.zones = make(map[string]Zone)
	}
	if zone, ok := p.zones[zoneName]; ok {
		return zone, nil
	}

	// Make API call to get zone
	reqURL := fmt.Sprintf("%s/zone/%s", p.Endpoint, zoneName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Zone{}, fmt.Errorf("failed to create request: %v", err)
	}

	var zone Zone
	_, err = p.sendAPIRequest(req, &zone)
	if err != nil {
		return Zone{}, fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Cache the zone
	p.zones[zoneName] = zone
	return zone, nil
}

// createZone creates a new zone via the AutoDNS API
func (p *Provider) createZone(ctx context.Context, zoneName string) error {
	reqURL := fmt.Sprintf("%s/zone", p.Endpoint)

	// Create zone with basic configuration
	zoneData := Zone{
		Origin: zoneName,
		SOA: &SOA{
			Refresh: 86400,   // 24 hours
			Retry:   7200,    // 2 hours
			Expire:  3600000, // 42 days
			TTL:     3600,    // 1 hour
		},
		DNSSEC:     false,
		WWWInclude: true,
	}

	requestBody := ZonePostRequest{
		Zone: zoneData,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal zone data: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	_, err = p.sendAPIRequest(req, nil)
	if err != nil {
		return fmt.Errorf("failed to create zone %s: %v", zoneName, err)
	}

	// Clear cache to force refresh
	p.zonesMutex.Lock()
	delete(p.zones, zoneName)
	p.zonesMutex.Unlock()

	return nil
}

// updateZone updates an existing zone via the AutoDNS API
func (p *Provider) updateZone(ctx context.Context, zoneName string, zoneData Zone) error {
	reqURL := fmt.Sprintf("%s/zone/%s", p.Endpoint, zoneName)

	requestBody := ZonePatchRequest{
		Zone: zoneData,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal zone data: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	_, err = p.sendAPIRequest(req, nil)
	if err != nil {
		return fmt.Errorf("failed to update zone %s: %v", zoneName, err)
	}

	return nil
}

// addRecords adds records to a zone
func (p *Provider) addRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		// If zone doesn't exist, try to create it
		if err := p.createZone(ctx, zoneName); err != nil {
			return fmt.Errorf("failed to create zone %s: %v", zoneName, err)
		}
		zoneData, err = p.getZone(ctx, zoneName)
		if err != nil {
			return fmt.Errorf("failed to get zone after creation: %v", err)
		}
	}

	// Convert libdns records to AutoDNS resource records
	var newRecords []ResourceRecord
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		newRecords = append(newRecords, rr)
	}

	// Add new records to existing ones
	zoneData.ResourceRecords = append(zoneData.ResourceRecords, newRecords...)

	// Update the zone
	return p.updateZone(ctx, zoneName, zoneData)
}

// setRecords replaces all records in a zone
func (p *Provider) setRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	// Convert libdns records to AutoDNS resource records
	var newRecords []ResourceRecord
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		newRecords = append(newRecords, rr)
	}

	// Get or create zone
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		// If zone doesn't exist, create it
		if err := p.createZone(ctx, zoneName); err != nil {
			return fmt.Errorf("failed to create zone %s: %v", zoneName, err)
		}
		zoneData, err = p.getZone(ctx, zoneName)
		if err != nil {
			return fmt.Errorf("failed to get zone after creation: %v", err)
		}
	}

	// Replace all records
	zoneData.ResourceRecords = newRecords

	// Update the zone
	return p.updateZone(ctx, zoneName, zoneData)
}

// deleteRecords removes specific records from a zone
func (p *Provider) deleteRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Create a map of records to delete for efficient lookup
	recordsToDelete := make(map[string]bool)
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		key := fmt.Sprintf("%s:%s:%s", rr.Type, rr.Name, rr.Value)
		recordsToDelete[key] = true
	}

	// Filter out records to delete
	var remainingRecords []ResourceRecord
	for _, rr := range zoneData.ResourceRecords {
		key := fmt.Sprintf("%s:%s:%s", rr.Type, rr.Name, rr.Value)
		if !recordsToDelete[key] {
			remainingRecords = append(remainingRecords, rr)
		}
	}

	// Update zone with remaining records
	zoneData.ResourceRecords = remainingRecords

	// Update the zone
	return p.updateZone(ctx, zoneName, zoneData)
}

// sendAPIRequest handles the HTTP request/response cycle with proper error handling
func (p *Provider) sendAPIRequest(req *http.Request, data any) (JsonResponse, error) {
	// Set authentication header
	if req.Header.Get("Authorization") == "" {
		auth := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(p.Username+":"+p.Password)))
		req.Header.Set("Authorization", auth)
	}

	// Set AutoDNS context header
	if req.Header.Get("X-Domainrobot-Context") == "" {
		req.Header.Set("X-Domainrobot-Context", p.Context)
	}

	// Set default headers
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "libdns-autodns/1.0")

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return JsonResponse{}, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var respData JsonResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return JsonResponse{}, fmt.Errorf("failed to decode response: %v", err)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return JsonResponse{}, fmt.Errorf("HTTP %d: %s - %s", resp.StatusCode, respData.Status.Code, respData.Status.Text)
	}

	// Check for API errors
	if respData.Status.Type == "ERROR" {
		return JsonResponse{}, fmt.Errorf("API error: %s - %s", respData.Status.Code, respData.Status.Text)
	}

	// Decode data if requested
	if len(respData.Data) > 0 && data != nil {
		if err := json.Unmarshal(respData.Data, data); err != nil {
			return JsonResponse{}, fmt.Errorf("failed to decode response data: %v", err)
		}
		respData.Data = nil
	}

	return respData, nil
}
