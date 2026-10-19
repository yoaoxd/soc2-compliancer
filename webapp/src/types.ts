export interface Org {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export interface Membership {
  org: Org;
  role: "admin" | "editor" | "viewer";
  created_at: string;
}

export interface UserSession {
  user: { id: string; email: string; display_name: string; created_at: string };
  orgs: Org[];
  memberships: Membership[];
  token: string;
}

export interface Control {
  id: string;
  edition: string;
  category: string;
  code: string;
  title: string;
  description: string;
}

export interface Mapping {
  id: string;
  control_id: string;
  control_code: string;
  provider: string;
  resource_type: string;
  guardrail: string;
  evidence_type: string;
}

export interface Var {
  name: string;
  type: string;
  required: boolean;
  default?: string;
}

export interface Component {
  provider: string;
  name: string;
  resource_types: string[];
  description: string;
  version: string;
  category: string;
  controls: string[];
  dependencies?: string[];
  tests?: string[];
  variables?: Var[];
}

export interface Provider {
  name: string;
  display_name: string;
  components: Component[];
}

export interface GenerateRequest {
  provider?: string;
  providers?: string[];
  components: {
    provider?: string;
    name: string;
    variables?: Record<string, string>;
  }[];
}

export interface GeneratedFile {
  path: string;
  content: string;
}

export interface GenerateResult {
  provider: string;
  providers?: string[];
  components: string[];
  controls: string[];
  warnings?: string[];
  files: GeneratedFile[];
}

export interface GenerationRecord {
  id: string;
  provider: string;
  providers?: string[];
  components: string[];
  controls: string[];
  created_at: string;
}

export interface Connection {
  id: string;
  provider: string;
  name: string;
  project_id: string;
  client_email: string;
  scan_interval_hours: number;
  last_scanned_at?: string;
  created_at: string;
}

export type CreateConnectionInput =
  | {
      provider: "gcp";
      name: string;
      service_account_json: string;
      scan_interval_hours?: number;
    }
  | {
      provider: "aws";
      name: string;
      aws_credentials: {
        region: string;
        access_key_id: string;
        secret_access_key: string;
        session_token?: string;
      };
      scan_interval_hours?: number;
    }
  | {
      provider: "azure";
      name: string;
      azure_credentials: {
        subscription_id: string;
        tenant_id: string;
        client_id: string;
        client_secret: string;
      };
      scan_interval_hours?: number;
    }
  | {
      provider: string;
      name: string;
      scan_interval_hours?: number;
      [k: string]: unknown;
    };

export interface Scan {
  id: string;
  connection_id: string;
  project_id: string;
  status: "running" | "completed" | "failed";
  error?: string;
  findings_count: number;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  connection_id: string;
  project_id: string;
  resource_type: string;
  resource_name: string;
  check_name: string;
  title: string;
  controls: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  evidence: Record<string, unknown>;
  remediation: {
    import_command: string;
    resource_address: string;
    resource_type: string;
    terraform_config: string;
    notes: string;
  };
  created_at: string;
}

export interface EvidenceControlRow {
  code: string;
  title: string;
  category: string;
  evidence_types: string[];
  guardrails: number;
  findings: Record<string, number>;
  open_findings: number;
  coverage: "covered" | "gaps" | "not_assessed";
}

export interface EvidenceMatrix {
  edition: string;
  scanned: boolean;
  controls: EvidenceControlRow[];
}

export interface CIRun {
  id: string;
  provider: string;
  tool: string;
  status: "passed" | "failed";
  findings: Record<string, unknown>[];
  created_at: string;
}