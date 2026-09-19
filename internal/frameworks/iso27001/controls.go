package iso27001

import (
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Annex A control IDs referenced by more than one policy. The catalog
// tables below stay the canonical list of all 93; these only name the
// entries the policy tables point at, so each reference is written once.
const (
	ctrlIdentityManagement      = "A.5.16" // Identity management
	ctrlAccessRights            = "A.5.18" // Access rights
	ctrlSupplierRelationships   = "A.5.19" // Information security in supplier relationships
	ctrlProtectionOfRecords     = "A.5.33" // Protection of records
	ctrlAccessRestriction       = "A.8.3"  // Information access restriction
	ctrlSourceCodeAccess        = "A.8.4"  // Access to source code
	ctrlSecureAuthentication    = "A.8.5"  // Secure authentication
	ctrlMalwareProtection       = "A.8.7"  // Protection against malware
	ctrlVulnerabilityManagement = "A.8.8"  // Management of technical vulnerabilities
	ctrlConfigurationManagement = "A.8.9"  // Configuration management
	ctrlDataLeakagePrevention   = "A.8.12" // Data leakage prevention
	ctrlInformationBackup       = "A.8.13" // Information backup
	ctrlLoggingControl          = "A.8.15" // Logging
	ctrlMonitoringActivities    = "A.8.16" // Monitoring activities
	ctrlNetworksSecurity        = "A.8.20" // Networks security
	ctrlNetworkServicesSecurity = "A.8.21" // Security of network services
	ctrlNetworkSegregation      = "A.8.22" // Segregation of networks
	ctrlCryptography            = "A.8.24" // Use of cryptography
	ctrlSecureDevelopment       = "A.8.25" // Secure development life cycle
	ctrlSecureCoding            = "A.8.28" // Secure coding
	ctrlSecurityTesting         = "A.8.29" // Security testing in development and acceptance
	ctrlChangeManagement        = "A.8.32" // Change management
)

// Management-system clause IDs, referenced by the clause evidence
// policies. ismsClauses below carries the full list with its titles.
const (
	clauseContext               = "C.4.1-4.2" // Context and interested parties
	clauseScope                 = "C.4.3"     // ISMS scope
	clauseSecurityPolicy        = "C.5.2"     // Information security policy
	clauseRoles                 = "C.5.3"     // Roles, responsibilities and authorities
	clauseRiskAssessmentProcess = "C.6.1.2"   // Risk assessment process
	clauseRiskTreatmentProcess  = "C.6.1.3"   // Risk treatment process
	clauseObjectives            = "C.6.2"     // Information security objectives
	clauseCompetence            = "C.7.2"     // Competence
	clauseDocumentedInformation = "C.7.5"     // Documented information
	clauseOperationalPlanning   = "C.8.1"     // Operational planning and control
	clauseRiskAssessmentResults = "C.8.2"     // Risk assessment results
	clauseRiskTreatmentResults  = "C.8.3"     // Risk treatment results
	clauseMonitoringMeasurement = "C.9.1"     // Monitoring, measurement, analysis and evaluation
	clauseInternalAudit         = "C.9.2"     // Internal audit
	clauseManagementReview      = "C.9.3"     // Management review
	clauseNonconformity         = "C.10.2"    // Nonconformity and corrective action
)

// Controls returns the full ISO/IEC 27001:2022 control catalog: the 93
// Annex A controls across the four themes (Organizational 5.x, People
// 6.x, Physical 7.x, Technological 8.x), plus the 16 management-system
// requirements of clauses 4-10.
//
// Certification is granted against the management system, not against
// Annex A in isolation: a Stage 1 audit is a documentation review of
// clauses 4-10, and an organization that satisfies every Annex A control
// and none of the clauses fails it. Shipping Annex A alone — as this
// framework did until the clauses were added — advertised a readiness it
// could not back, and, because every coverage surface is built on this
// function, reported 93/93 over a universe that was missing a third of
// what the auditor asks for.
//
// The two are distinguishable by ControlKind rather than by parsing the
// ID prefix: clause controls are ControlKindManagementSystem, cannot be
// declared not_applicable, and never appear in a Statement of
// Applicability. Reading the prefix instead would be wrong as well as
// brittle — a project-local extension's controls carry neither prefix
// and still belong in the SoA.
func Controls() []core.Control {
	out := make([]core.Control, 0, 93+len(ismsClauses))
	out = append(out, themeControls("Organizational", catGovernance, organizational)...)
	out = append(out, themeControls("People", catGovernance, people)...)
	out = append(out, themeControls("Physical", "physical", physical)...)
	out = append(out, themeControls("Technological", "technical", technological)...)
	out = append(out, clauseControls()...)
	return out
}

// AnnexAControls returns only the Annex A catalog — the controls an
// organization selects from and that a Statement of Applicability
// reports on.
func AnnexAControls() []core.Control {
	all := Controls()
	out := make([]core.Control, 0, len(all))
	for i := range all {
		if !all[i].IsManagementSystem() {
			out = append(out, all[i])
		}
	}
	return out
}

// clauseControls expands the management-system clauses into controls.
// The ID carries a "C." prefix so it cannot be read as an Annex A
// reference: clause 5.2 (the information security policy) and A.5.2
// (information security roles) are different requirements that an
// auditor checks separately.
func clauseControls() []core.Control {
	out := make([]core.Control, 0, len(ismsClauses))
	for _, d := range ismsClauses {
		out = append(out, core.Control{
			ID:               d.id,
			Name:             d.name,
			Description:      d.name + " (ISO/IEC 27001:2022 clause " + strings.TrimPrefix(d.id, "C.") + ", management system).",
			Category:         "isms",
			BaselineSeverity: core.SeverityMedium,
			Kind:             core.ControlKindManagementSystem,
		})
	}
	return out
}

// ismsClauses is the Stage 1 reading list: the documented information
// ISO/IEC 27001:2022 requires of the management system itself, plus the
// three records every certification audit asks for without the standard
// strictly mandating a document — C.4.1-4.2 (the context and
// interested-parties analysis, whose output 6.1.1 and 9.3.2 b consume),
// C.5.3 (the assignment of ISMS roles) and C.7.5 (the document
// register). They are included because an auditor will ask, and
// labeled honestly here because a set that claims to be "the mandatory
// documented information" while quietly exceeding it would be the same
// species of overclaim this framework is being fixed for.
//
// Clause numbers are the standard's own. 6.1.3's Statement of
// Applicability is absent on purpose: SigComply generates it (report
// --view soa) rather than asking for it to be uploaded.
var ismsClauses = []ctrlDef{
	{"C.4.1-4.2", "Organizational context and the needs of interested parties"},
	{"C.4.3", "Scope of the information security management system"},
	{"C.5.2", "Information security policy"},
	{"C.5.3", "Organizational roles, responsibilities and authorities"},
	{"C.6.1.2", "Information security risk assessment process"},
	{"C.6.1.3", "Information security risk treatment process"},
	{"C.6.2", "Information security objectives and planning to achieve them"},
	{"C.7.2", "Competence"},
	{"C.7.5", "Documented information"},
	{"C.8.1", "Operational planning and control"},
	{"C.8.2", "Information security risk assessment results"},
	{"C.8.3", "Information security risk treatment results"},
	{"C.9.1", "Monitoring, measurement, analysis and evaluation"},
	{"C.9.2", "Internal audit"},
	{"C.9.3", "Management review"},
	{"C.10.2", "Nonconformity and corrective action"},
}

type ctrlDef struct {
	id   string
	name string
}

func themeControls(theme, category string, defs []ctrlDef) []core.Control {
	out := make([]core.Control, 0, len(defs))
	for _, d := range defs {
		out = append(out, core.Control{
			ID:               d.id,
			Name:             d.name,
			Description:      d.name + " (ISO/IEC 27001:2022 Annex A " + d.id + ", " + theme + ").",
			Category:         category,
			BaselineSeverity: core.SeverityMedium,
		})
	}
	return out
}

var organizational = []ctrlDef{
	{"A.5.1", "Policies for information security"},
	{"A.5.2", "Information security roles and responsibilities"},
	{"A.5.3", "Segregation of duties"},
	{"A.5.4", "Management responsibilities"},
	{"A.5.5", "Contact with authorities"},
	{"A.5.6", "Contact with special interest groups"},
	{"A.5.7", "Threat intelligence"},
	{"A.5.8", "Information security in project management"},
	{"A.5.9", "Inventory of information and other associated assets"},
	{"A.5.10", "Acceptable use of information and other associated assets"},
	{"A.5.11", "Return of assets"},
	{"A.5.12", "Classification of information"},
	{"A.5.13", "Labeling of information"},
	{"A.5.14", "Information transfer"},
	{"A.5.15", "Access control"},
	{"A.5.16", "Identity management"},
	{"A.5.17", "Authentication information"},
	{"A.5.18", "Access rights"},
	{"A.5.19", "Information security in supplier relationships"},
	{"A.5.20", "Addressing information security within supplier agreements"},
	{"A.5.21", "Managing information security in the ICT supply chain"},
	{"A.5.22", "Monitoring, review and change management of supplier services"},
	{"A.5.23", "Information security for use of cloud services"},
	{"A.5.24", "Information security incident management planning and preparation"},
	{"A.5.25", "Assessment and decision on information security events"},
	{"A.5.26", "Response to information security incidents"},
	{"A.5.27", "Learning from information security incidents"},
	{"A.5.28", "Collection of evidence"},
	{"A.5.29", "Information security during disruption"},
	{"A.5.30", "ICT readiness for business continuity"},
	{"A.5.31", "Legal, statutory, regulatory and contractual requirements"},
	{"A.5.32", "Intellectual property rights"},
	{"A.5.33", "Protection of records"},
	{"A.5.34", "Privacy and protection of PII"},
	{"A.5.35", "Independent review of information security"},
	{"A.5.36", "Compliance with policies, rules and standards for information security"},
	{"A.5.37", "Documented operating procedures"},
}

var people = []ctrlDef{
	{"A.6.1", "Screening"},
	{"A.6.2", "Terms and conditions of employment"},
	{"A.6.3", "Information security awareness, education and training"},
	{"A.6.4", "Disciplinary process"},
	{"A.6.5", "Responsibilities after termination or change of employment"},
	{"A.6.6", "Confidentiality or non-disclosure agreements"},
	{"A.6.7", "Remote working"},
	{"A.6.8", "Information security event reporting"},
}

var physical = []ctrlDef{
	{"A.7.1", "Physical security perimeters"},
	{"A.7.2", "Physical entry"},
	{"A.7.3", "Securing offices, rooms and facilities"},
	{"A.7.4", "Physical security monitoring"},
	{"A.7.5", "Protecting against physical and environmental threats"},
	{"A.7.6", "Working in secure areas"},
	{"A.7.7", "Clear desk and clear screen"},
	{"A.7.8", "Equipment siting and protection"},
	{"A.7.9", "Security of assets off-premises"},
	{"A.7.10", "Storage media"},
	{"A.7.11", "Supporting utilities"},
	{"A.7.12", "Cabling security"},
	{"A.7.13", "Equipment maintenance"},
	{"A.7.14", "Secure disposal or re-use of equipment"},
}

var technological = []ctrlDef{
	{"A.8.1", "User end point devices"},
	{"A.8.2", "Privileged access rights"},
	{"A.8.3", "Information access restriction"},
	{"A.8.4", "Access to source code"},
	{"A.8.5", "Secure authentication"},
	{"A.8.6", "Capacity management"},
	{"A.8.7", "Protection against malware"},
	{"A.8.8", "Management of technical vulnerabilities"},
	{"A.8.9", "Configuration management"},
	{"A.8.10", "Information deletion"},
	{"A.8.11", "Data masking"},
	{"A.8.12", "Data leakage prevention"},
	{"A.8.13", "Information backup"},
	{"A.8.14", "Redundancy of information processing facilities"},
	{"A.8.15", "Logging"},
	{"A.8.16", "Monitoring activities"},
	{"A.8.17", "Clock synchronization"},
	{"A.8.18", "Use of privileged utility programs"},
	{"A.8.19", "Installation of software on operational systems"},
	{"A.8.20", "Networks security"},
	{"A.8.21", "Security of network services"},
	{"A.8.22", "Segregation of networks"},
	{"A.8.23", "Web filtering"},
	{"A.8.24", "Use of cryptography"},
	{"A.8.25", "Secure development life cycle"},
	{"A.8.26", "Application security requirements"},
	{"A.8.27", "Secure system architecture and engineering principles"},
	{"A.8.28", "Secure coding"},
	{"A.8.29", "Security testing in development and acceptance"},
	{"A.8.30", "Outsourced development"},
	{"A.8.31", "Separation of development, test and production environments"},
	{"A.8.32", "Change management"},
	{"A.8.33", "Test information"},
	{"A.8.34", "Protection of information systems during audit testing"},
}
