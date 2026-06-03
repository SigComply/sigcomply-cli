package iso27001

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// manualPolicies returns every manual-evidence ISO 27001 policy as a
// core.Policy across the organizational (5.x), people (6.x), physical
// (7.x), and technological (8.x) themes.
func manualPolicies() []core.Policy {
	specs := manualSpecs()
	out := make([]core.Policy, len(specs))
	for i := range specs {
		out[i] = specs[i].policy()
	}
	return out
}

// manualSpecs is the single authoring list for ISO 27001 manual
// evidence. Both the policy library (manualPolicies) and the descriptive
// catalog export (ManualCatalogExport) derive from it. Most entries are
// document_upload; the handful the Evidence SPA can render as a form
// carry an explicit etype + items/declarationText.
func manualSpecs() []manualPolicy {
	out := make([]manualPolicy, 0, 48)
	out = append(out, organizationalManualSpecs()...)
	out = append(out, peopleManualSpecs()...)
	out = append(out, physicalManualSpecs()...)
	out = append(out, technologicalManualSpecs()...)
	return out
}

func organizationalManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.5.1.information_security_policies", control: "A.5.1", cadence: "annual", catalog: "information_security_policies", desc: "A complete set of information security policies is approved by management.", rem: "Upload the approved IS policy suite."},
		{id: "iso27001.5.2.roles_and_responsibilities", control: "A.5.2", cadence: "annual", catalog: "roles_and_responsibilities", desc: "Information security roles and responsibilities are defined.", rem: "Upload the security roles and responsibilities document."},
		{id: "iso27001.5.4.management_direction", control: "A.5.4", cadence: "annual", catalog: "management_direction", desc: "Management direction for information security is documented.", rem: "Upload evidence of management direction for security."},
		{id: "iso27001.5.5.contact_with_authorities", control: "A.5.5", cadence: "annual", catalog: "contact_with_authorities", desc: "Contacts with relevant authorities are maintained.", rem: "Upload the authority-contact register."},
		{id: "iso27001.5.8.information_security_in_projects", control: "A.5.8", cadence: "annual", catalog: "information_security_in_projects", desc: "Information security is integrated into project management.", rem: "Upload evidence of security in project management."},
		{id: "iso27001.5.9.asset_inventory", control: "A.5.9", cadence: "annual", catalog: "asset_inventory", desc: "An inventory of information assets is maintained.", rem: "Upload the asset inventory."},
		{id: "iso27001.5.10.acceptable_use_policy", control: "A.5.10", cadence: "annual", catalog: "acceptable_use_policy", desc: "An acceptable use policy for assets exists.", rem: "Upload the acceptable use policy."},
		{id: "iso27001.5.12.data_classification_policy", control: "A.5.12", cadence: "annual", catalog: "data_classification_policy", desc: "A data classification policy exists.", rem: "Upload the data classification policy."},
		{id: "iso27001.5.13.information_labeling_policy", control: "A.5.13", cadence: "annual", catalog: "information_labeling_policy", desc: "An information labeling policy exists.", rem: "Upload the information labeling policy."},
		{id: "iso27001.5.14.information_transfer_policy", control: "A.5.14", cadence: "annual", catalog: "information_transfer_policy", desc: "An information transfer policy exists.", rem: "Upload the information transfer policy."},
		{id: "iso27001.5.18.access_rights_review", control: "A.5.18", cadence: "quarterly", catalog: "access_rights_review", desc: "A periodic access rights review is performed.", rem: "Upload the access rights review evidence."},
		{id: "iso27001.5.19.supplier_security_policy", control: "A.5.19", cadence: "annual", catalog: "supplier_security_policy", desc: "A supplier security policy exists.", rem: "Upload the supplier security policy."},
		{id: "iso27001.5.20.supplier_security_agreements", control: "A.5.20", cadence: "annual", catalog: "supplier_security_agreements", desc: "Supplier agreements address information security.", rem: "Upload supplier agreements with security clauses."},
		{id: "iso27001.5.22.supplier_service_monitoring", control: "A.5.22", cadence: "annual", catalog: "supplier_service_monitoring", desc: "Supplier service delivery is monitored.", rem: "Upload supplier service monitoring evidence."},
		{id: "iso27001.5.24.incident_management_plan", control: "A.5.24", cadence: "annual", catalog: "incident_management_plan", desc: "An incident management plan exists.", rem: "Upload the incident management plan."},
		{id: "iso27001.5.26.incident_response_tested", control: "A.5.26", cadence: "annual", catalog: "incident_response_tested", desc: "Incident response is tested.", rem: "Upload incident response test results.",
			etype: manualcatalog.TypeChecklist,
			items: []manualcatalog.ChecklistItem{
				{ID: "plan_tested", Text: "Incident response plan was tested via tabletop exercise or simulation", Required: true},
				{ID: "roles_verified", Text: "All incident response roles and responsibilities were verified", Required: true},
				{ID: "communication_tested", Text: "Communication channels and escalation paths were tested", Required: true},
				{ID: "lessons_documented", Text: "Lessons learned were documented and the plan updated accordingly", Required: false},
			},
		},
		{id: "iso27001.5.27.lessons_learned_from_incidents", control: "A.5.27", cadence: "annual", catalog: "lessons_learned_from_incidents", desc: "Lessons are learned from incidents.", rem: "Upload incident lessons-learned documentation."},
		{id: "iso27001.5.29.information_security_in_bcp", control: "A.5.29", cadence: "annual", catalog: "information_security_in_bcp", desc: "Information security is maintained during disruption.", rem: "Upload the security-in-continuity plan."},
		{id: "iso27001.5.30.ict_continuity_tested", control: "A.5.30", cadence: "annual", catalog: "ict_continuity_tested", desc: "ICT continuity is tested.", rem: "Upload ICT continuity test results.",
			etype: manualcatalog.TypeChecklist,
			items: []manualcatalog.ChecklistItem{
				{ID: "continuity_executed", Text: "ICT continuity arrangements were exercised against a representative scenario", Required: true},
				{ID: "objectives_met", Text: "Recovery objectives (RTO/RPO) were met", Required: true},
				{ID: "gaps_remediated", Text: "Gaps identified during the test were documented and remediated", Required: false},
			},
		},
		{id: "iso27001.5.31.legal_requirements_inventory", control: "A.5.31", cadence: "annual", catalog: "legal_requirements_inventory", desc: "Legal, statutory, and contractual requirements are inventoried.", rem: "Upload the legal requirements register."},
		{id: "iso27001.5.34.privacy_and_pii_protection", control: "A.5.34", cadence: "annual", catalog: "privacy_and_pii_protection", desc: "Privacy and PII protection requirements are documented.", rem: "Upload the privacy and PII protection policy."},
		{id: "iso27001.5.35.independent_security_review", control: "A.5.35", cadence: "annual", catalog: "independent_security_review", desc: "Information security is independently reviewed.", rem: "Upload the independent security review report."},
		{id: "iso27001.5.36.compliance_with_policies", control: "A.5.36", cadence: "annual", catalog: "compliance_with_policies", desc: "Compliance with security policies is monitored and attested.", rem: "Upload the compliance attestation.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that compliance with the organization's information security policies and standards has been reviewed during this period and that identified non-conformities have been recorded and addressed.",
		},
	}
}

func peopleManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.6.1.personnel_screening", control: "A.6.1", cadence: "annual", catalog: "personnel_screening", desc: "Personnel are screened prior to employment.", rem: "Upload the personnel screening process."},
		{id: "iso27001.6.2.terms_of_employment", control: "A.6.2", cadence: "annual", catalog: "terms_of_employment", desc: "Employment terms include security responsibilities.", rem: "Upload employment terms with security clauses."},
		{id: "iso27001.6.3.security_awareness_training", control: "A.6.3", cadence: "annual", catalog: "security_awareness_training", desc: "Personnel complete security awareness training.", rem: "Upload security awareness training records."},
		{id: "iso27001.6.4.disciplinary_process", control: "A.6.4", cadence: "annual", catalog: "disciplinary_process", desc: "A disciplinary process for security violations exists.", rem: "Upload the disciplinary process."},
		{id: "iso27001.6.5.responsibilities_on_termination", control: "A.6.5", cadence: "annual", catalog: "responsibilities_on_termination", desc: "Security responsibilities persist after termination.", rem: "Upload the post-termination responsibilities document."},
		{id: "iso27001.6.6.nda_confidentiality_agreement", control: "A.6.6", cadence: "annual", catalog: "nda_confidentiality_agreement", desc: "Confidentiality / non-disclosure agreements are in place.", rem: "Upload the NDA / confidentiality agreement.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that all personnel and relevant third parties with access to organizational information have signed confidentiality / non-disclosure agreements that remain in force during this period.",
		},
	}
}

func physicalManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.7.1.physical_security_perimeters", control: "A.7.1", cadence: "annual", catalog: "physical_security_perimeters", desc: "Physical security perimeters are defined.", rem: "Upload the physical security perimeter documentation."},
		{id: "iso27001.7.2.physical_entry_controls", control: "A.7.2", cadence: "annual", catalog: "physical_entry_controls", desc: "Physical entry controls are implemented.", rem: "Upload the physical entry control documentation."},
		{id: "iso27001.7.4.physical_security_monitoring", control: "A.7.4", cadence: "annual", catalog: "physical_security_monitoring", desc: "Physical security is monitored.", rem: "Upload physical security monitoring evidence."},
		{id: "iso27001.7.7.clear_desk_clear_screen_policy", control: "A.7.7", cadence: "annual", catalog: "clear_desk_clear_screen_policy", desc: "A clear-desk / clear-screen policy exists.", rem: "Upload the clear-desk / clear-screen policy."},
		{id: "iso27001.7.10.storage_media_policy", control: "A.7.10", cadence: "annual", catalog: "storage_media_policy", desc: "A storage media handling policy exists.", rem: "Upload the storage media policy."},
		{id: "iso27001.7.14.secure_disposal_policy", control: "A.7.14", cadence: "annual", catalog: "secure_disposal_policy", desc: "A secure disposal / reuse policy for equipment exists.", rem: "Upload the secure disposal policy."},
	}
}

func technologicalManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.8.1.endpoint_device_policy", control: "A.8.1", cadence: "annual", catalog: "endpoint_device_policy", desc: "An endpoint / user device security policy exists.", rem: "Upload the endpoint device policy."},
		{id: "iso27001.8.6.capacity_management_process", control: "A.8.6", cadence: "annual", catalog: "capacity_management_process", desc: "A capacity management process exists.", rem: "Upload the capacity management process."},
		{id: "iso27001.8.10.information_deletion_policy", control: "A.8.10", cadence: "annual", catalog: "information_deletion_policy", desc: "An information deletion policy exists.", rem: "Upload the information deletion policy."},
		{id: "iso27001.8.19.software_installation_policy", control: "A.8.19", cadence: "annual", catalog: "software_installation_policy", desc: "A software installation policy for operational systems exists.", rem: "Upload the software installation policy."},
		{id: "iso27001.8.23.web_filtering_policy", control: "A.8.23", cadence: "annual", catalog: "web_filtering_policy", desc: "A web filtering policy exists.", rem: "Upload the web filtering policy."},
		{id: "iso27001.8.26.application_security_requirements", control: "A.8.26", cadence: "annual", catalog: "application_security_requirements", desc: "Application security requirements are defined.", rem: "Upload the application security requirements."},
		{id: "iso27001.8.27.secure_architecture_principles", control: "A.8.27", cadence: "annual", catalog: "secure_architecture_principles", desc: "Secure system architecture principles are documented.", rem: "Upload the secure architecture principles."},
		{id: "iso27001.8.30.outsourced_development_policy", control: "A.8.30", cadence: "annual", catalog: "outsourced_development_policy", desc: "Outsourced development is governed and monitored.", rem: "Upload the outsourced development policy."},
		{id: "iso27001.8.33.test_information_policy", control: "A.8.33", cadence: "annual", catalog: "test_information_policy", desc: "Test information is protected.", rem: "Upload the test information policy."},
		{id: "iso27001.8.34.audit_testing_protection_policy", control: "A.8.34", cadence: "annual", catalog: "audit_testing_protection_policy", desc: "Audit testing of operational systems is controlled.", rem: "Upload the audit testing protection policy."},
		{id: "iso27001.8.32.change_management_policy", control: "A.8.32", cadence: "annual", catalog: "change_management_policy", desc: "A change management policy exists.", rem: "Upload the change management policy."},
	}
}
