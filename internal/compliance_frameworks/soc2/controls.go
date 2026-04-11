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
	{
		ID:          "CC6.4",
		Name:        "Physical Access Restriction",
		Description: "The entity restricts physical access to facilities and protected information assets to authorized personnel.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC6.5",
		Name:        "Media Disposal",
		Description: "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required to meet the entity's objectives.",
		Category:    "Logical and Physical Access Controls",
		Severity:    evidence.SeverityHigh,
	},
	// CC1 - Control Environment
	{
		ID:          "CC1.2",
		Name:        "Board Oversight",
		Description: "The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.",
		Category:    "Control Environment",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC1.4",
		Name:        "Competence",
		Description: "The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.",
		Category:    "Control Environment",
		Severity:    evidence.SeverityHigh,
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
		ID:          "CC3.1",
		Name:        "Risk Assessment Objectives",
		Description: "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
		Category:    "Risk Assessment",
		Severity:    evidence.SeverityHigh,
	},
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
	{
		ID:          "CC3.4",
		Name:        "Changes That Impact Internal Control",
		Description: "The entity identifies and assesses changes that could significantly impact the system of internal control.",
		Category:    "Risk Assessment",
		Severity:    evidence.SeverityHigh,
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
		ID:          "CC9.1",
		Name:        "Business Disruption Risk Mitigation",
		Description: "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions, including the use of insurance.",
		Category:    "Risk Mitigation",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC9.2",
		Name:        "Vendor and Business Partner Risk Management",
		Description: "The entity assesses and manages risks associated with vendors and business partners.",
		Category:    "Risk Mitigation",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "CC9.3",
		Name:        "Risk Mitigation Activities",
		Description: "The entity identifies and assesses changes that could significantly impact the system of internal controls.",
		Category:    "Risk Mitigation",
		Severity:    evidence.SeverityMedium,
	},

	// A1 - Availability
	{
		ID:          "A1.1",
		Name:        "Capacity Planning",
		Description: "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to meet its availability objectives.",
		Category:    "Availability",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A1.2",
		Name:        "Recovery and Continuity",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to meet its availability objectives.",
		Category:    "Availability",
		Severity:    evidence.SeverityHigh,
	},
	{
		ID:          "A1.3",
		Name:        "Recovery Plan Testing",
		Description: "The entity tests recovery plan procedures supporting system recovery to meet its availability objectives.",
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

	// CC1.1 - Commitment to Integrity and Ethics
	{
		ID:          "CC1.1",
		Name:        "Commitment to Integrity and Ethics",
		Description: "The entity demonstrates a commitment to integrity and ethical values through its code of conduct and related acknowledgments.",
		Category:    "Control Environment",
		Severity:    evidence.SeverityHigh,
	},

	// CC2.2 - Internal Communication
	{
		ID:          "CC2.2",
		Name:        "Internal Communication",
		Description: "The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control.",
		Category:    "Communication and Information",
		Severity:    evidence.SeverityMedium,
	},

	// CC5.3 - Policies and Procedures
	{
		ID:          "CC5.3",
		Name:        "Policies and Procedures",
		Description: "The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action, including periodic review of those policies.",
		Category:    "Control Activities",
		Severity:    evidence.SeverityMedium,
	},

	// P1 - Privacy Notice
	{
		ID:          "P1.1",
		Name:        "Privacy Notice",
		Description: "The entity provides notice to data subjects about its privacy practices to meet the entity's privacy-related objectives.",
		Category:    "Privacy",
		Severity:    evidence.SeverityHigh,
	},

	// P2 - Choice and Consent
	{
		ID:          "P2.1",
		Name:        "Privacy Consent and Choice",
		Description: "The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information to data subjects and obtains consent as required.",
		Category:    "Privacy",
		Severity:    evidence.SeverityHigh,
	},

	// P3 - Collection
	{
		ID:          "P3.1",
		Name:        "Collection of Personal Information",
		Description: "The entity limits the collection of personal information to that which is necessary for the purposes identified in the privacy notice (data minimization).",
		Category:    "Privacy",
		Severity:    evidence.SeverityMedium,
	},

	// P5 - Access
	{
		ID:          "P5.2",
		Name:        "Data Subject Access and Requests",
		Description: "The entity provides data subjects the ability to access, update, correct, and request deletion of their personal information, and responds to requests in a timely manner.",
		Category:    "Privacy",
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
