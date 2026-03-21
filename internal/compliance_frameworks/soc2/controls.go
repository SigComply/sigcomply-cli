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
	// CC1.5 - Service Control Policies
	{
		ID:          "CC1.5",
		Name:        "Control Activities for Policies",
		Description: "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
		Category:    "Control Environment",
		Severity:    evidence.SeverityMedium,
	},

	// CC3 - Risk Assessment
	{
		ID:          "CC3.2",
		Name:        "Risk Identification",
		Description: "The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.",
		Category:    "Risk Assessment",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC3.3",
		Name:        "Fraud Risk Assessment",
		Description: "The entity considers the potential for fraud in assessing risks to the achievement of objectives.",
		Category:    "Risk Assessment",
		Severity:    evidence.SeverityMedium,
	},

	// CC4 - Monitoring Activities
	{
		ID:          "CC4.1",
		Name:        "Monitoring Controls",
		Description: "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
		Category:    "Monitoring Activities",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC4.2",
		Name:        "Deficiency Communication",
		Description: "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action.",
		Category:    "Monitoring Activities",
		Severity:    evidence.SeverityHigh,
	},

	// CC6.6 - Network Security
	{
		ID:          "CC6.6",
		Name:        "Network Security",
		Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityHigh,
	},
	// CC6.7 - Data Transmission Security
	{
		ID:          "CC6.7",
		Name:        "Data Transmission Security",
		Description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityHigh,
	},
	// CC6.8 - Malicious Software Prevention
	{
		ID:          "CC6.8",
		Name:        "Malicious Software Prevention",
		Description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
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

	// CC5 - Control Activities
	{
		ID:          "CC5.1",
		Name:        "Control Activities Selection",
		Description: "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels, including permission boundaries and least privilege governance.",
		Category:    "Control Activities",
		Severity:    evidence.SeverityMedium,
	},

	// CC7.3 - Security Event Evaluation
	{
		ID:          "CC7.3",
		Name:        "Security Event Evaluation",
		Description: "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.",
		Category:    "System Operations",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC7.4",
		Name:        "Incident Response Execution",
		Description: "The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate.",
		Category:    "System Operations",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC7.5",
		Name:        "Security Incident Recovery",
		Description: "The entity identifies, develops, and implements activities to recover from identified security incidents.",
		Category:    "System Operations",
		Severity:    evidence.SeverityHigh,
	},

	// CC2 - Communication and Information
	{
		ID:          "CC2.1",
		Name:        "Communication and Information",
		Description: "The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.",
		Category:    "Communication and Information",
		Severity:    evidence.SeverityMedium,
	},

	// CC9 - Risk Mitigation
	{
		ID:          "CC9.3",
		Name:        "Risk Mitigation Activities",
		Description: "The entity identifies and assesses changes that could significantly impact the system of internal controls.",
		Category:    "Risk Mitigation",
		Severity:    evidence.SeverityMedium,
	},

	// A1 - Availability
	{
		ID:          "A1.2",
		Name:        "Recovery and Continuity",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to meet its availability objectives.",
		Category:    "Availability",
		Severity:    evidence.SeverityHigh,
	},

	// PI - Processing Integrity
	{
		ID:          "PI1.3",
		Name:        "Processing Integrity Monitoring",
		Description: "The entity implements processing integrity monitoring procedures to detect processing errors and deviations, using logging, validation, and monitoring controls.",
		Category:    "Processing Integrity",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "PI1.4",
		Name:        "Processing Integrity Data Protection",
		Description: "The entity implements controls to protect data integrity during processing, including encryption of data at rest and in transit to prevent unauthorized modification.",
		Category:    "Processing Integrity",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "PI1.5",
		Name:        "Processing Integrity Storage Protection",
		Description: "The entity implements controls to ensure the integrity and protection of stored data, including versioning, immutability, encryption, and key management.",
		Category:    "Processing Integrity",
		Severity:    evidence.SeverityHigh,
	},

	// C1 - Confidentiality
	{
		ID:          "C1.2",
		Name:        "Confidentiality Disposal",
		Description: "The entity disposes of confidential information to meet the entity's objectives related to confidentiality, including data lifecycle management.",
		Category:    "Confidentiality",
		Severity:    evidence.SeverityMedium,
	},
	{
		ID:          "C1.1",
		Name:        "Confidentiality Protection",
		Description: "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
		Category:    "Confidentiality",
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
