// Package iso27001 provides the ISO 27001 compliance framework implementation.
package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core/evidence"

// ISO 27001:2022 Annex A Controls
// Reference: ISO/IEC 27001:2022

// controls defines all ISO 27001 controls supported by SigComply.
var controls = []Control{
	// A.5 - Organizational Controls
	{
		ID:          "A.5.1",
		Name:        "Policies for Information Security",
		Description: "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.",
		Category:    "Organizational Controls",
		Severity:    evidence.SeverityMedium,
	},

	// A.8 - Technological Controls
	{
		ID:          "A.8.2",
		Name:        "Privileged Access Rights",
		Description: "The allocation and use of privileged access rights shall be restricted and managed.",
		Category:    "Technological Controls",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A.8.5",
		Name:        "Secure Authentication",
		Description: "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
		Category:    "Technological Controls",
		Severity:    evidence.SeverityHigh,
	},

	// A.9 - Access Control (ISO 27001:2013 numbering, still commonly referenced)
	{
		ID:          "A.9.2.1",
		Name:        "User Access Provisioning",
		Description: "A formal user access provisioning process shall be implemented to assign or revoke access rights for all user types to all systems and services.",
		Category:    "Access Control",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A.9.2.3",
		Name:        "Management of Privileged Access Rights",
		Description: "The allocation and use of privileged access rights shall be restricted and controlled.",
		Category:    "Access Control",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A.9.4.2",
		Name:        "Secure Log-on Procedures",
		Description: "Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure.",
		Category:    "Access Control",
		Severity:    evidence.SeverityHigh,
	},

	// A.12 - Operations Security
	{
		ID:          "A.12.4.1",
		Name:        "Event Logging",
		Description: "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
		Category:    "Operations Security",
		Severity:    evidence.SeverityCritical,
	},
	{
		ID:          "A.12.4.2",
		Name:        "Protection of Log Information",
		Description: "Logging facilities and log information shall be protected against tampering and unauthorized access.",
		Category:    "Operations Security",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A.12.4.3",
		Name:        "Administrator and Operator Logs",
		Description: "System administrator and system operator activities shall be logged and the logs protected and regularly reviewed.",
		Category:    "Operations Security",
		Severity:    evidence.SeverityHigh,
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

// GetControls returns all ISO 27001 controls.
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
