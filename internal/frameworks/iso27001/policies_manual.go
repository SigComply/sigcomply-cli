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
	out := make([]manualPolicy, 0, 72)
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
		{id: "iso27001.5.6.special_interest_groups", control: "A.5.6", cadence: "annual", catalog: "special_interest_groups", desc: "Contact with special interest groups and security forums is maintained.", rem: "Upload the special interest group membership register."},
		{id: "iso27001.5.7.threat_intelligence", control: "A.5.7", cadence: "annual", catalog: "threat_intelligence", desc: "Threat intelligence is collected and analyzed.", rem: "Upload the threat intelligence process or recent threat intelligence reports."},
		{id: "iso27001.5.8.information_security_in_projects", control: "A.5.8", cadence: "annual", catalog: "information_security_in_projects", desc: "Information security is integrated into project management.", rem: "Upload evidence of security in project management."},
		{id: "iso27001.5.9.asset_inventory", control: "A.5.9", cadence: "annual", catalog: "asset_inventory", desc: "An inventory of information assets is maintained.", rem: "Upload the asset inventory."},
		{id: "iso27001.5.10.acceptable_use_policy", control: "A.5.10", cadence: "annual", catalog: "acceptable_use_policy", desc: "An acceptable use policy for assets exists.", rem: "Upload the acceptable use policy."},
		{id: "iso27001.5.11.return_of_assets", control: "A.5.11", cadence: "annual", catalog: "return_of_assets", desc: "Assets are returned when employment or engagement ends.", rem: "Upload the signed asset-return declaration.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that all organizational assets issued to personnel and third parties whose employment or engagement ended during this period have been returned or verifiably wiped, and that the return has been recorded.",
		},
		{id: "iso27001.5.12.data_classification_policy", control: "A.5.12", cadence: "annual", catalog: "data_classification_policy", desc: "A data classification policy exists.", rem: "Upload the data classification policy."},
		{id: "iso27001.5.13.information_labeling_policy", control: "A.5.13", cadence: "annual", catalog: "information_labeling_policy", desc: "An information labeling policy exists.", rem: "Upload the information labeling policy."},
		{id: "iso27001.5.14.information_transfer_policy", control: "A.5.14", cadence: "annual", catalog: "information_transfer_policy", desc: "An information transfer policy exists.", rem: "Upload the information transfer policy."},
		{id: "iso27001.5.18.access_rights_review", control: "A.5.18", cadence: "quarterly", catalog: "access_rights_review", desc: "A periodic access rights review is performed.", rem: "Upload the access rights review evidence."},
		{id: "iso27001.5.19.supplier_security_policy", control: "A.5.19", cadence: "annual", catalog: "supplier_security_policy", desc: "A supplier security policy exists.", rem: "Upload the supplier security policy."},
		{id: "iso27001.5.20.supplier_security_agreements", control: "A.5.20", cadence: "annual", catalog: "supplier_security_agreements", desc: "Supplier agreements address information security.", rem: "Upload supplier agreements with security clauses."},
		{id: "iso27001.5.21.ict_supply_chain_security", control: "A.5.21", cadence: "annual", catalog: "ict_supply_chain_security", desc: "Information security is managed across the ICT supply chain.", rem: "Upload the ICT supply chain security policy."},
		{id: "iso27001.5.22.supplier_service_monitoring", control: "A.5.22", cadence: "annual", catalog: "supplier_service_monitoring", desc: "Supplier service delivery is monitored.", rem: "Upload supplier service monitoring evidence."},
		{id: "iso27001.5.23.cloud_services_security", control: "A.5.23", cadence: "annual", catalog: "cloud_services_security", desc: "Information security requirements for the use of cloud services are defined.", rem: "Upload the cloud services security policy."},
		{id: "iso27001.5.24.incident_management_plan", control: "A.5.24", cadence: "annual", catalog: "incident_management_plan", desc: "An incident management plan exists.", rem: "Upload the incident management plan."},
		{id: "iso27001.5.25.security_event_assessment", control: "A.5.25", cadence: "annual", catalog: "security_event_assessment", desc: "Security events are assessed and classified before being declared incidents.", rem: "Upload the security event assessment and classification procedure."},
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
		{id: "iso27001.5.28.evidence_collection_procedure", control: "A.5.28", cadence: "annual", catalog: "evidence_collection_procedure", desc: "Evidence relating to security events is identified, collected, and preserved.", rem: "Upload the evidence collection and preservation procedure."},
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
		{id: "iso27001.5.32.intellectual_property_rights", control: "A.5.32", cadence: "annual", catalog: "intellectual_property_rights", desc: "Intellectual property rights are respected.", rem: "Upload the signed intellectual property rights declaration.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that the organization complies with legislative, regulatory, and contractual requirements for intellectual property rights and software licensing, and that no unlicensed software is knowingly used on organizational systems during this period.",
		},
		{id: "iso27001.5.34.privacy_and_pii_protection", control: "A.5.34", cadence: "annual", catalog: "privacy_and_pii_protection", desc: "Privacy and PII protection requirements are documented.", rem: "Upload the privacy and PII protection policy."},
		{id: "iso27001.5.35.independent_security_review", control: "A.5.35", cadence: "annual", catalog: "independent_security_review", desc: "Information security is independently reviewed.", rem: "Upload the independent security review report."},
		{id: "iso27001.5.36.compliance_with_policies", control: "A.5.36", cadence: "annual", catalog: "compliance_with_policies", desc: "Compliance with security policies is monitored and attested.", rem: "Upload the compliance attestation.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that compliance with the organization's information security policies and standards has been reviewed during this period and that identified non-conformities have been recorded and addressed.",
		},
		{id: "iso27001.5.37.documented_operating_procedures", control: "A.5.37", cadence: "annual", catalog: "documented_operating_procedures", desc: "Operating procedures for information processing facilities are documented.", rem: "Upload the documented operating procedures / runbooks."},
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
		{id: "iso27001.6.7.remote_working_policy", control: "A.6.7", cadence: "annual", catalog: "remote_working_policy", desc: "A remote working policy protects information accessed outside the organization's premises.", rem: "Upload the remote working policy."},
		{id: "iso27001.6.8.security_event_reporting", control: "A.6.8", cadence: "annual", catalog: "security_event_reporting", desc: "Personnel have a defined channel for reporting information security events.", rem: "Upload the security event reporting procedure."},
	}
}

func physicalManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.7.1.physical_security_perimeters", control: "A.7.1", cadence: "annual", catalog: "physical_security_perimeters", desc: "Physical security perimeters are defined.", rem: "Upload the physical security perimeter documentation."},
		{id: "iso27001.7.2.physical_entry_controls", control: "A.7.2", cadence: "annual", catalog: "physical_entry_controls", desc: "Physical entry controls are implemented.", rem: "Upload the physical entry control documentation."},
		{id: "iso27001.7.3.securing_offices_and_facilities", control: "A.7.3", cadence: "annual", catalog: "securing_offices_and_facilities", desc: "Offices, rooms, and facilities holding information assets are physically secured.", rem: "Upload the hosting or facility provider's SOC 2 / ISO 27001 certificate covering the facilities, or the security documentation for any office or facility the organization operates itself."},
		{id: "iso27001.7.4.physical_security_monitoring", control: "A.7.4", cadence: "annual", catalog: "physical_security_monitoring", desc: "Physical security is monitored.", rem: "Upload physical security monitoring evidence."},
		{id: "iso27001.7.5.physical_and_environmental_threats", control: "A.7.5", cadence: "annual", catalog: "physical_and_environmental_threats", desc: "Facilities holding information assets are protected against physical and environmental threats.", rem: "Upload the hosting provider's SOC 2 / ISO 27001 certificate covering environmental protection, or the environmental threat protection documentation for a facility the organization operates itself."},
		{id: "iso27001.7.6.working_in_secure_areas", control: "A.7.6", cadence: "annual", catalog: "working_in_secure_areas", desc: "Rules for working in secure areas are defined and followed.", rem: "Upload the signed secure-area working declaration.",
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that secure areas within the organization's control are identified and that the rules for working in them are defined and followed during this period, and that where the organization operates no secure areas of its own, the hosting facilities are run by a third-party provider under its own certified controls.",
		},
		{id: "iso27001.7.7.clear_desk_clear_screen_policy", control: "A.7.7", cadence: "annual", catalog: "clear_desk_clear_screen_policy", desc: "A clear-desk / clear-screen policy exists.", rem: "Upload the clear-desk / clear-screen policy."},
		{id: "iso27001.7.8.equipment_siting_protection", control: "A.7.8", cadence: "annual", catalog: "equipment_siting_protection", desc: "Equipment holding information assets is sited and protected against physical risk.", rem: "Upload the hosting provider's SOC 2 / ISO 27001 certificate covering equipment siting and protection, or the siting documentation for equipment the organization operates itself."},
		{id: "iso27001.7.9.assets_off_premises", control: "A.7.9", cadence: "annual", catalog: "assets_off_premises", desc: "Assets used away from the organization's premises are protected.", rem: "Upload the off-premises asset protection policy covering laptops and other devices used outside organization premises."},
		{id: "iso27001.7.10.storage_media_policy", control: "A.7.10", cadence: "annual", catalog: "storage_media_policy", desc: "A storage media handling policy exists.", rem: "Upload the storage media policy."},
		{id: "iso27001.7.11.supporting_utilities", control: "A.7.11", cadence: "annual", catalog: "supporting_utilities", desc: "Information processing facilities are protected from failure of supporting utilities.", rem: "Upload the hosting provider's SOC 2 / ISO 27001 certificate covering power and cooling, or the supporting-utility documentation for a facility the organization operates itself."},
		{id: "iso27001.7.12.cabling_security", control: "A.7.12", cadence: "annual", catalog: "cabling_security", desc: "Cabling carrying power and data is protected from interception and damage.", rem: "Upload the hosting provider's SOC 2 / ISO 27001 certificate covering cabling, or the cabling security documentation for a facility the organization operates itself."},
		{id: "iso27001.7.13.equipment_maintenance", control: "A.7.13", cadence: "annual", catalog: "equipment_maintenance", desc: "Equipment is maintained so that information stays available and intact.", rem: "Upload the hosting provider's SOC 2 / ISO 27001 certificate covering equipment maintenance, or the maintenance records for equipment the organization operates itself."},
		{id: "iso27001.7.14.secure_disposal_policy", control: "A.7.14", cadence: "annual", catalog: "secure_disposal_policy", desc: "A secure disposal / reuse policy for equipment exists.", rem: "Upload the secure disposal policy."},
	}
}

func technologicalManualSpecs() []manualPolicy {
	return []manualPolicy{
		{id: "iso27001.8.1.endpoint_device_policy", control: "A.8.1", cadence: "annual", catalog: "endpoint_device_policy", desc: "An endpoint / user device security policy exists.", rem: "Upload the endpoint device policy."},
		{id: "iso27001.8.6.capacity_management_process", control: "A.8.6", cadence: "annual", catalog: "capacity_management_process", desc: "A capacity management process exists.", rem: "Upload the capacity management process."},
		{id: "iso27001.8.10.information_deletion_policy", control: "A.8.10", cadence: "annual", catalog: "information_deletion_policy", desc: "An information deletion policy exists.", rem: "Upload the information deletion policy."},
		{id: "iso27001.8.11.data_masking_policy", control: "A.8.11", cadence: "annual", catalog: "data_masking_policy", desc: "Data masking is applied where required to limit exposure of sensitive data.", rem: "Upload the data masking policy."},
		{id: "iso27001.8.17.clock_synchronization", control: "A.8.17", cadence: "annual", catalog: "clock_synchronization", desc: "System clocks are synchronized to an approved time source.", rem: "Upload the clock synchronization standard and evidence of its configuration."},
		{id: "iso27001.8.18.privileged_utility_programs", control: "A.8.18", cadence: "annual", catalog: "privileged_utility_programs", desc: "Use of privileged utility programs is restricted and controlled.", rem: "Upload the privileged utility program policy."},
		{id: "iso27001.8.19.software_installation_policy", control: "A.8.19", cadence: "annual", catalog: "software_installation_policy", desc: "A software installation policy for operational systems exists.", rem: "Upload the software installation policy."},
		{id: "iso27001.8.23.web_filtering_policy", control: "A.8.23", cadence: "annual", catalog: "web_filtering_policy", desc: "A web filtering policy exists.", rem: "Upload the web filtering policy."},
		{id: "iso27001.8.26.application_security_requirements", control: "A.8.26", cadence: "annual", catalog: "application_security_requirements", desc: "Application security requirements are defined.", rem: "Upload the application security requirements."},
		{id: "iso27001.8.27.secure_architecture_principles", control: "A.8.27", cadence: "annual", catalog: "secure_architecture_principles", desc: "Secure system architecture principles are documented.", rem: "Upload the secure architecture principles."},
		{id: "iso27001.8.30.outsourced_development_policy", control: "A.8.30", cadence: "annual", catalog: "outsourced_development_policy", desc: "Outsourced development is governed and monitored.", rem: "Upload the outsourced development policy."},
		{id: "iso27001.8.31.environment_separation", control: "A.8.31", cadence: "annual", catalog: "environment_separation", desc: "Development, test, and production environments are separated.", rem: "Upload the environment separation evidence.",
			etype: manualcatalog.TypeChecklist,
			items: []manualcatalog.ChecklistItem{
				{ID: "environments_separated", Text: "Development, test, and production run as separate, isolated environments", Required: true},
				{ID: "access_separated", Text: "Access to production is granted separately from development and test access", Required: true},
				{ID: "promotion_controlled", Text: "Changes reach production only through a controlled promotion process", Required: true},
				{ID: "production_data_controlled", Text: "Production data is not copied into development or test environments without approval and masking", Required: false},
			},
		},
		{id: "iso27001.8.33.test_information_policy", control: "A.8.33", cadence: "annual", catalog: "test_information_policy", desc: "Test information is protected.", rem: "Upload the test information policy."},
		{id: "iso27001.8.34.audit_testing_protection_policy", control: "A.8.34", cadence: "annual", catalog: "audit_testing_protection_policy", desc: "Audit testing of operational systems is controlled.", rem: "Upload the audit testing protection policy."},
		{id: "iso27001.8.32.change_management_policy", control: "A.8.32", cadence: "annual", catalog: "change_management_policy", desc: "A change management policy exists.", rem: "Upload the change management policy."},
	}
}
