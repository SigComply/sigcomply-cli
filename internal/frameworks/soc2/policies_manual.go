package soc2

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// manualPolicies returns every manual-evidence SOC 2 policy as a
// core.Policy (the shape the evaluator and registry consume).
func manualPolicies() []core.Policy {
	specs := manualSpecs()
	out := make([]core.Policy, len(specs))
	for i := range specs {
		out[i] = specs[i].policy()
	}
	return out
}

// manualSpecs is the single authoring list for SOC 2 manual evidence.
// Both the policy library (manualPolicies) and the descriptive catalog
// export (ManualCatalogExport) derive from it, so the policy and its
// catalog metadata cannot drift. Most entries are document_upload
// (externally-produced PDFs); the handful the Evidence SPA can render as
// a clickable form carry an explicit etype + items/declarationText.
func manualSpecs() []manualPolicy {
	return []manualPolicy{
		// CC1 — Control environment.
		{id: "soc2.cc1.1.security_awareness_training", control: "CC1.1", cadence: cadenceAnnual, catalog: "security_awareness_training", desc: "Employees complete security awareness training.", rem: "Upload evidence of completed security awareness training.", tsc: tscSecurity},
		{id: "soc2.cc1.1.code_of_conduct_acknowledgment", control: "CC1.1", cadence: cadenceAnnual, catalog: "code_of_conduct_acknowledgment", desc: "Employees acknowledge the code of conduct.", rem: "Upload signed code-of-conduct acknowledgements.", tsc: tscSecurity,
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that all personnel have acknowledged the organization's code of conduct during this period, either on hire or as part of the annual re-acknowledgment.",
		},
		{id: "soc2.cc1.2.board_security_oversight", control: "CC1.2", cadence: cadenceAnnual, catalog: "board_security_oversight", desc: "The board exercises security oversight.", rem: "Upload board/exec security review minutes.", tsc: tscSecurity},
		{id: "soc2.cc1.3.org_chart_security_roles", control: "CC1.3", cadence: cadenceAnnual, catalog: "org_chart_security_roles", desc: "An org chart documents security responsibilities.", rem: "Upload an org chart showing security roles.", tsc: tscSecurity},
		{id: "soc2.cc1.4.background_check_policy", control: "CC1.4", cadence: cadenceAnnual, catalog: "background_check_policy", desc: "A background-check process is documented.", rem: "Upload the background-check policy.", tsc: tscSecurity},
		{id: "soc2.cc1.5.accountability_for_controls", control: "CC1.5", cadence: cadenceAnnual, catalog: "accountability_for_controls", desc: "Individuals are held accountable for their internal-control responsibilities.", rem: "Upload evidence that security responsibilities are defined in role descriptions and evaluated in performance reviews.", tsc: tscSecurity,
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that internal-control and information-security responsibilities are defined for each role, that individuals were evaluated against those responsibilities during this period, and that failures to meet them are addressed through the organization's performance and disciplinary processes.",
		},

		// CC2 — Communication and information.
		{id: "soc2.cc2.1.information_security_policy", control: "CC2.1", cadence: cadenceAnnual, catalog: "information_security_policy", desc: "A written information security policy exists.", rem: "Upload the approved information security policy.", tsc: tscSecurity},
		{id: "soc2.cc2.2.internal_security_communication", control: "CC2.2", cadence: cadenceAnnual, catalog: "internal_security_communication", desc: "Security responsibilities are communicated internally.", rem: "Upload evidence of internal security communications.", tsc: tscSecurity},
		{id: "soc2.cc2.3.external_security_communication", control: "CC2.3", cadence: cadenceAnnual, catalog: "external_security_communication", desc: "Security commitments, changes and incidents are communicated to external parties.", rem: "Upload evidence of external security communication — trust/security page, customer security notices, status-page or breach-notification procedure.", tsc: tscSecurity},

		// CC3 — Risk assessment.
		{id: "soc2.cc3.1.risk_assessment", control: "CC3.1", cadence: cadenceAnnual, catalog: "risk_assessment", desc: "An annual risk assessment is performed.", rem: "Upload the latest risk assessment.", tsc: tscSecurity},
		{id: "soc2.cc3.2.fraud_risk_assessment", control: "CC3.2", cadence: cadenceAnnual, catalog: "fraud_risk_assessment", desc: "Fraud risk is assessed.", rem: "Upload the fraud risk assessment.", tsc: tscSecurity},
		{id: "soc2.cc3.3.fraud_risk_considered", control: "CC3.3", cadence: cadenceAnnual, catalog: "fraud_risk_considered", desc: "The potential for fraud is explicitly considered when assessing risks.", rem: "Confirm that fraud scenarios — including management override of controls — were considered in this period's risk assessment.", tsc: tscSecurity,
			etype:           manualcatalog.TypeDeclaration,
			declarationText: "I confirm that the potential for fraud was explicitly considered when assessing risks during this period, including management override of controls, incentives and pressures to commit fraud, and opportunities arising from privileged system access.",
		},
		{id: "soc2.cc3.4.change_risk_assessment", control: "CC3.4", cadence: cadenceAnnual, catalog: "change_risk_assessment", desc: "Significant changes that could impact the system of internal control are identified and assessed.", rem: "Upload the assessment of significant changes — new systems, new vendors, organizational or regulatory changes — and their impact on controls.", tsc: tscSecurity},

		// CC4 — Monitoring activities.
		{id: "soc2.cc4.1.control_monitoring", control: "CC4.1", cadence: cadenceQuarterly, catalog: "control_monitoring", desc: "Controls are monitored on an ongoing basis.", rem: "Upload evidence of ongoing control monitoring.", tsc: tscSecurity},
		{id: "soc2.cc4.2.control_deficiency_communication", control: "CC4.2", cadence: cadenceQuarterly, catalog: "control_deficiency_communication", desc: "Internal-control deficiencies are evaluated and communicated to those responsible for corrective action.", rem: "Upload the deficiency / remediation tracker showing each finding, its owner, severity, and closure date.", tsc: tscSecurity},

		// CC5 — Control activities.
		{id: "soc2.cc5.1.control_selection_rationale", control: "CC5.1", cadence: cadenceAnnual, catalog: "control_selection_rationale", desc: "Control design rationale is documented.", rem: "Upload the control selection rationale.", tsc: tscSecurity},
		{id: "soc2.cc5.2.technology_control_activities", control: "CC5.2", cadence: cadenceAnnual, catalog: "technology_control_activities", desc: "General control activities over technology are selected and developed to support the achievement of objectives.", rem: "Upload documentation of the technology general controls in place — access, change and operations — and the rationale for their selection.", tsc: tscSecurity},
		{id: "soc2.cc5.3.technology_controls_deployment", control: "CC5.3", cadence: cadenceAnnual, catalog: "technology_controls_deployment", desc: "Technology controls are deployed per policy.", rem: "Upload evidence of technology control deployment.", tsc: tscSecurity},

		// CC6 — Logical access (manual portions).
		{id: "soc2.cc6.3.access_review_quarterly", control: "CC6.3", cadence: cadenceQuarterly, catalog: "access_review_quarterly", desc: "A quarterly user access review is performed and signed.", rem: "Upload the signed quarterly access review.", tsc: tscSecurity},
		{id: "soc2.cc6.4.subservice_org_reports", control: "CC6.4", cadence: cadenceAnnual, catalog: "subservice_org_reports", desc: "Physical access to facilities hosting the system is restricted; for cloud-hosted infrastructure this control is carried by the subservice organization.", rem: "Upload the current SOC 2 or ISO 27001 report for each infrastructure subservice organization (AWS, GCP, Azure), or evidence of physical access controls for any facility you operate yourself.", tsc: tscSecurity},
		{id: "soc2.cc6.5.termination_access_removal_process", control: ctrlCC65, cadence: cadenceAnnual, catalog: "termination_process_documented", desc: "An offboarding access-removal process is documented.", rem: "Upload the user offboarding procedure.", tsc: tscSecurity},
		{id: "soc2.cc6.1.privileged_access_policy", control: ctrlCC61, cadence: cadenceAnnual, catalog: "privileged_access_policy", desc: "A privileged access management policy exists.", rem: "Upload the privileged access management policy.", tsc: tscSecurity},
		{id: "soc2.cc6.2.user_provisioning_process", control: ctrlCC62, cadence: cadenceAnnual, catalog: "user_provisioning_process", desc: "A user provisioning/onboarding SOP exists.", rem: "Upload the user provisioning procedure.", tsc: tscSecurity},
		{id: "soc2.cc6.6.network_segmentation_policy", control: ctrlCC66, cadence: cadenceAnnual, catalog: "network_segmentation_policy", desc: "A network segmentation policy exists.", rem: "Upload the network segmentation policy.", tsc: tscSecurity},
		{id: "soc2.cc6.6.firewall_review_policy", control: ctrlCC66, cadence: cadenceAnnual, catalog: "firewall_review_policy", desc: "A firewall-rule review process is documented.", rem: "Upload the firewall review policy.", tsc: tscSecurity},
		{id: "soc2.cc6.7.data_classification_policy", control: ctrlCC67, cadence: cadenceAnnual, catalog: "data_classification_policy", desc: "A data classification policy exists.", rem: "Upload the data classification policy.", tsc: tscSecurity},

		// CC7 — System operations (manual portions).
		{id: "soc2.cc7.1.log_review_process", control: ctrlCC71, cadence: cadenceAnnual, catalog: "log_review_process", desc: "A log review and alerting process is documented.", rem: "Upload the log review process.", tsc: tscSecurity},
		{id: "soc2.cc7.3.incident_response_plan", control: ctrlCC73, cadence: cadenceAnnual, catalog: "incident_response_plan", desc: "An incident response plan exists.", rem: "Upload the incident response plan.", tsc: tscSecurity},
		{id: "soc2.cc7.3.incident_response_tested", control: ctrlCC73, cadence: cadenceAnnual, catalog: "incident_response_tested", desc: "The incident response plan is tested.", rem: "Upload incident response test results.", tsc: tscSecurity,
			etype: manualcatalog.TypeChecklist,
			items: []manualcatalog.ChecklistItem{
				{ID: "plan_tested", Text: "Incident response plan was tested via tabletop exercise or simulation", Required: true},
				{ID: "roles_verified", Text: "All incident response roles and responsibilities were verified", Required: true},
				{ID: "communication_tested", Text: "Communication channels and escalation paths were tested", Required: true},
				{ID: "lessons_documented", Text: "Lessons learned were documented and the plan updated accordingly", Required: false},
			},
		},
		{id: "soc2.cc7.3.security_monitoring_policy", control: ctrlCC73, cadence: cadenceAnnual, catalog: "security_monitoring_policy", desc: "A security monitoring and alerting policy exists.", rem: "Upload the security monitoring policy.", tsc: tscSecurity},
		{id: "soc2.cc7.4.vulnerability_disclosure_policy", control: "CC7.4", cadence: cadenceAnnual, catalog: "vulnerability_disclosure_policy", desc: "A vulnerability disclosure policy exists.", rem: "Upload the vulnerability disclosure policy.", tsc: tscSecurity},

		// CC8 — Change management (manual portions).
		{id: "soc2.cc8.1.change_management_policy", control: ctrlCC81, cadence: cadenceAnnual, catalog: "change_management_policy", desc: "A change management policy exists.", rem: "Upload the change management policy.", tsc: tscSecurity},
		{id: "soc2.cc8.1.security_sdlc_process", control: ctrlCC81, cadence: cadenceAnnual, catalog: "security_sdlc_process", desc: "A secure SDLC process is documented.", rem: "Upload the secure SDLC process.", tsc: tscSecurity},
		{id: "soc2.cc8.1.penetration_test_annual", control: ctrlCC81, cadence: cadenceAnnual, catalog: "penetration_test_annual", desc: "An annual penetration test is performed.", rem: "Upload the latest penetration test report.", tsc: tscSecurity},
		{id: "soc2.cc8.1.vulnerability_management_policy", control: ctrlCC81, cadence: cadenceAnnual, catalog: "vulnerability_management_policy", desc: "A vulnerability management policy exists.", rem: "Upload the vulnerability management policy.", tsc: tscSecurity},
		{id: "soc2.cc8.1.code_review_policy", control: ctrlCC81, cadence: cadenceAnnual, catalog: "code_review_policy", desc: "Code review requirements are documented.", rem: "Upload the code review policy.", tsc: tscSecurity},

		// CC9 — Vendor / third-party risk.
		{id: "soc2.cc9.1.vendor_risk_assessment", control: "CC9.1", cadence: cadenceAnnual, catalog: "vendor_risk_assessment", desc: "Third-party / vendor risk is assessed.", rem: "Upload the vendor risk assessment.", tsc: tscSecurity},
		{id: "soc2.cc9.1.due_diligence_process", control: "CC9.1", cadence: cadenceAnnual, catalog: "due_diligence_process", desc: "A vendor due-diligence process is documented.", rem: "Upload the vendor due-diligence process.", tsc: tscSecurity},
		{id: "soc2.cc9.2.vendor_contracts_reviewed", control: ctrlCC92, cadence: cadenceAnnual, catalog: "vendor_contracts_reviewed", desc: "Vendor contracts include security clauses.", rem: "Upload reviewed vendor contracts with security clauses.", tsc: tscSecurity},
		// Fans out over the project's third-party register: one folder
		// per vendor, so "we have a vendor assessment" becomes "we have
		// one for each vendor that needs it". Without a register
		// declared this behaves exactly like any other single-folder
		// entry. See docs/guides/vendor-risk.md.
		{id: "soc2.cc9.2.vendor_assurance", control: ctrlCC92, cadence: cadenceAnnual, catalog: "vendor_assurance", fanOut: manual.FanOutVendors, name: "Vendor Assurance Evidence", desc: "Each vendor in the third-party register has current assurance evidence on file.", rem: "For each vendor, upload their current SOC 2 Type II report, ISO 27001 certificate, penetration-test summary, or completed security questionnaire into that vendor's folder.", tsc: tscSecurity},
		// Fans out over the subservice organizations only: CUECs are
		// the controls a subservice organization's own report assumes
		// *you* operate, so they are per-organization by nature.
		{id: "soc2.cc9.2.cuec_mapping", control: ctrlCC92, cadence: cadenceAnnual, catalog: "cuec_mapping", fanOut: manual.FanOutSubserviceVendors, name: "Complementary User Entity Controls Mapping", desc: "Complementary user entity controls (CUECs) from each subservice organization's report are mapped to controls this organization operates.", rem: "For each subservice organization, upload a mapping of the CUECs listed in their report to the controls you operate. Note these are CUECs — what their report expects you to do — not complementary subservice organization controls (CSOCs), which are what you expect of them.", tsc: tscSecurity},

		// A1 — Availability (manual portions).
		{id: "soc2.a1.2.business_continuity_plan", control: ctrlA12, cadence: cadenceAnnual, catalog: "business_continuity_plan", desc: "A business continuity plan exists.", rem: "Upload the business continuity plan.", tsc: tscAvailability},
		{id: "soc2.a1.3.recovery_procedures_tested", control: "A1.3", cadence: cadenceAnnual, catalog: "recovery_procedures_tested", desc: "Disaster-recovery procedures are tested.", rem: "Upload DR/recovery test results.", tsc: tscAvailability,
			etype: manualcatalog.TypeChecklist,
			items: []manualcatalog.ChecklistItem{
				{ID: "recovery_executed", Text: "Recovery procedures were executed against a representative scenario", Required: true},
				{ID: "rto_rpo_met", Text: "Recovery time and recovery point objectives (RTO/RPO) were met", Required: true},
				{ID: "data_integrity_verified", Text: "Restored data integrity was verified", Required: true},
				{ID: "gaps_remediated", Text: "Gaps identified during the test were documented and remediated", Required: false},
			},
		},

		// C1 — Confidentiality (manual portions).
		{id: "soc2.c1.2.data_retention_policy", control: "C1.2", cadence: cadenceAnnual, catalog: "data_retention_policy", desc: "A data retention policy exists.", rem: "Upload the data retention policy.", tsc: tscConfidentiality},
		{id: "soc2.c1.3.nda_policy", control: "C1.3", cadence: cadenceAnnual, catalog: "nda_policy", desc: "An NDA policy and template exist.", rem: "Upload the NDA policy and template.", tsc: tscConfidentiality},

		// P-series — Privacy.
		{id: "soc2.p1.1.privacy_notice", control: "P1.1", cadence: cadenceAnnual, catalog: "privacy_notice", desc: "A privacy notice is published.", rem: "Upload the privacy notice.", tsc: tscPrivacy},
		{id: "soc2.p3.1.data_collection_policy", control: "P3.1", cadence: cadenceAnnual, catalog: "data_collection_policy", desc: "A data collection and use policy exists.", rem: "Upload the data collection policy.", tsc: tscPrivacy},
		{id: "soc2.p6.1.data_retention_disposal", control: "P6.1", cadence: cadenceAnnual, catalog: "data_retention_disposal", desc: "A data retention and disposal policy exists.", rem: "Upload the data retention and disposal policy.", tsc: tscPrivacy},

		// PI1 — Processing integrity.
		{id: "soc2.pi1.1.processing_integrity_policy", control: "PI1.1", cadence: cadenceAnnual, catalog: "processing_integrity_policy", desc: "Processing integrity is documented.", rem: "Upload the processing integrity documentation.", tsc: "processing_integrity"},
	}
}
