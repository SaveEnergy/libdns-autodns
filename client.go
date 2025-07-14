package autodns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	// Try to get the zone - the API might return an array or a single object
	var zones []Zone
	_, err = p.sendAPIRequest(req, &zones)
	if err != nil {
		return Zone{}, fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Handle array response - take first zone if multiple
	var zone Zone
	if len(zones) > 0 {
		zone = zones[0]
	} else {
		return Zone{}, fmt.Errorf("no zones found for %s", zoneName)
	}

	// Cache the zone
	p.zones[zoneName] = zone
	return zone, nil
}

// setZone updates a zone via the AutoDNS API
func (p *Provider) setZone(ctx context.Context, zoneName string, zoneData Zone) error {
	reqURL := fmt.Sprintf("%s/zone/%s", p.Endpoint, zoneName)

	// Clean up the zone data to remove invalid timestamps and unnecessary fields
	cleanZone := Zone{
		Origin:            zoneData.Origin,
		SOA:               zoneData.SOA,
		NameServers:       zoneData.NameServers,
		ResourceRecords:   zoneData.ResourceRecords,
		WWWInclude:        zoneData.WWWInclude,
		VirtualNameServer: zoneData.VirtualNameServer,
		Action:            zoneData.Action,
		ROID:              zoneData.ROID,
		// Explicitly exclude timestamp fields that might cause issues
		// Created, Updated, PurgeDate, Date are not included
	}

	requestBody := cleanZone

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal zone data: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	_, err = p.sendAPIRequest(req, nil)
	if err != nil {
		return fmt.Errorf("failed to update zone %s: %v", zoneName, err)
	}

	// Clear cache after update to ensure fresh data
	p.zonesMutex.Lock()
	delete(p.zones, zoneName)
	p.zonesMutex.Unlock()

	return nil
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

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return JsonResponse{}, fmt.Errorf("failed to read response body: %v", err)
	}

	// Try to parse as JsonResponse first
	var respData JsonResponse
	if err := json.Unmarshal(body, &respData); err == nil {
		// Successfully parsed as JsonResponse
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
		}
		return respData, nil
	}

	// If not a JsonResponse, try to parse directly as the expected data type
	if data != nil {
		if err := json.Unmarshal(body, data); err != nil {
			return JsonResponse{}, fmt.Errorf("failed to decode response as %T: %v", data, err)
		}
	}

	// Return empty response for direct data responses
	return JsonResponse{}, nil
}

// addRecords adds records to a zone
func (p *Provider) addRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	// Get the current zone
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Convert libdns records to AutoDNS resource records
	var newRecords []ResourceRecord
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		newRecords = append(newRecords, rr)
	}

	// Add new records to existing ones (preserve existing records)
	zoneData.ResourceRecords = append(zoneData.ResourceRecords, newRecords...)

	// Update the zone
	return p.setZone(ctx, zoneName, zoneData)
}

// setRecords updates existing records or creates new ones, preserving other records
func (p *Provider) setRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	// Get the current zone
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Convert new records to AutoDNS format
	var newRecords []ResourceRecord
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		newRecords = append(newRecords, rr)
	}

	// Create a set of type/name combinations to replace
	recordsToReplace := make(map[string]bool)
	for _, rr := range newRecords {
		// Use full domain name
		key := fmt.Sprintf("%s:%s", rr.Type, rr.Name)
		recordsToReplace[key] = true

		// Also use subdomain name (without zone suffix)
		shortName := strings.TrimSuffix(rr.Name, "."+zoneName)
		shortKey := fmt.Sprintf("%s:%s", rr.Type, shortName)
		recordsToReplace[shortKey] = true
	}

	// Filter out existing records that match the type/name of records we want to set
	var preservedRecords []ResourceRecord
	for _, rr := range zoneData.ResourceRecords {
		key := fmt.Sprintf("%s:%s", rr.Type, rr.Name)
		if !recordsToReplace[key] {
			// Keep records that don't match the type/name of records we're setting
			preservedRecords = append(preservedRecords, rr)
		}
		// Skip records that match the type/name of records we're setting (they will be replaced)
	}

	// Combine preserved records with new records
	zoneData.ResourceRecords = append(preservedRecords, newRecords...)

	// Update the zone
	return p.setZone(ctx, zoneName, zoneData)
}

// deleteRecords removes specific records from a zone
func (p *Provider) deleteRecords(ctx context.Context, zoneName string, records []libdns.Record) error {
	// Get the current zone
	zoneData, err := p.getZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone %s: %v", zoneName, err)
	}

	// Create a map of records to delete for efficient lookup
	// We need to be more specific to avoid deleting records with same type/name but different values
	recordsToDelete := make(map[string]bool)
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		// Use a more specific key that includes part of the value to avoid false matches
		key := fmt.Sprintf("%s:%s:%s", rr.Type, rr.Name, rr.Value)
		recordsToDelete[key] = true
	}

	// Also create a map for records without the full domain name (as they appear in the zone)
	for _, record := range records {
		rr := libdnsRecordToResourceRecord(record, zoneName)
		// Remove the zone name from the record name to match how it appears in the zone
		shortName := strings.TrimSuffix(rr.Name, "."+zoneName)
		key := fmt.Sprintf("%s:%s:%s", rr.Type, shortName, rr.Value)
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
	zoneData.ResourceRecords = remainingRecords

	// Update the zone
	return p.setZone(ctx, zoneName, zoneData)
}
