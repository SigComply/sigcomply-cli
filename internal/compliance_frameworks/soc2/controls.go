// Package soc2 provides the SOC 2 compliance framework implementation.
package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core/evidence"

// SOC 2 Trust Service Criteria Controls
// Reference: AICPA Trust Services Criteria (2017)

// controls defines all SOC 2 controls supported by SigComply.
var controls = []Control{
	// CC6 - Logical and Physical Access Controls
	{
		ID:          "CC6.1",
		Name:        "Logical Access Security",
		Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC6.2",
		Name:        "Data Protection",
		Description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityMedium,
	},
	{
		ID:          "CC6.3",
		Name:        "Access Removal",
		Description: "The entity removes access to protected information assets when appropriate.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityMedium,
	},

	// CC7 - System Operations
	{
		ID:          "CC7.1",
		Name:        "Monitoring and Detection",
		Description: "To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
		Category:    "System Operations",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC7.2",
		Name:        "Security Event Monitoring",
		Description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events.",
		Category:    "System Operations",
		Severity:    evidence.SeverityHigh,
	},

	// CC8 - Change Management
	{
		ID:          "CC8.1",
		Name:        "Change Management",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
		Category:    "Change Management",
		Severity:    evidence.SeverityMedium,
	},
}

// Control is an alias for the engine.Control type for convenience.
type Control = struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Severity    evidence.Severity `json:"severity"`
}

// GetControls returns all SOC 2 controls.
func GetControls() []Control {
	return controls
}

// GetControl returns a specific control by ID.
func GetControl(id string) *Control {
	for i := range controls {
		if controls[i].ID == id {
			return &controls[i]
		}
	}
	return nil
}

// GetControlsByCategory returns controls filtered by category.
func GetControlsByCategory(category string) []Control {
	var result []Control
	for i := range controls {
		if controls[i].Category == category {
			result = append(result, controls[i])
		}
	}
	return result
}

// Categories returns all unique control categories.
func Categories() []string {
	seen := make(map[string]bool)
	var categories []string
	for i := range controls {
		if !seen[controls[i].Category] {
			seen[controls[i].Category] = true
			categories = append(categories, controls[i].Category)
		}
	}
	return categories
}
