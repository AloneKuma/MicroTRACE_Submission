variable "aws_profile" {
  description = "CLI profile that assumes the MicroTRACE-Terraform role."
  type        = string
  default     = "microtrace"
}

variable "session" {
  description = "Short session name (tags, resource names), e.g. s1-baselines."
  type        = string
}

variable "availability_zone" {
  description = "Zone priced for Spot on 2026-11-11 (m7i.8xlarge cheapest in us-east-1c and 1f). Re-check before each session."
  type        = string
  default     = "us-east-1c"
}

variable "ami_id" {
  description = "Ubuntu 24.04 (kernel 6.8) base AMI (noble 20261004), as decided 2026-10-08. Re-check the latest before each session."
  type        = string
  default     = "ami-0fa5967347d08d2df"
}

variable "analysis_type" {
  description = "One analysis host for every compared system (decision 2026-11-11): 32 vCPU, 128 GB, PTP hardware clock."
  type        = string
  default     = "m7i.8xlarge"
}

variable "disk_gb" {
  description = "Analysis host root disk: FIT + both held-out sets, conversion, database, artifacts, outputs."
  type        = number
  default     = 1200
}

variable "analysis_profile" {
  description = "Instance profile from ../storage (output analysis_instance_profile): no truth reads."
  type        = string
  default     = "MicroTRACE-heldout-analysis"
}

variable "scoring_profile" {
  description = "Instance profile from ../storage (output scoring_instance_profile): truth reads, scoring session only."
  type        = string
  default     = "MicroTRACE-heldout-scoring"
}

variable "scoring" {
  description = "true only for the single scoring session after every detection output is in S3."
  type        = bool
  default     = false
}

variable "senders" {
  description = "Exp. 3 sender nodes (replayers, fault injector). 0 for sessions without live transport."
  type        = number
  default     = 0
}

variable "sender_type" {
  type    = string
  default = "m7i.xlarge"
}

variable "kind_node" {
  description = "Exp. 5 kind cluster node (GRE target)."
  type        = bool
  default     = false
}

variable "kind_type" {
  type    = string
  default = "m7i.2xlarge"
}

variable "placement" {
  description = "Cluster placement group for all nodes of the session (off if capacity is short)."
  type        = bool
  default     = true
}

variable "spot" {
  description = "Spot instances (~1/3 price) for sessions without timed passes; on-demand for the timing session."
  type        = bool
  default     = false
}

variable "max_hours" {
  description = "Every machine shuts down (and terminates) this many hours after first boot. Set per session (A ~12, B ~24, timing ~12)."
  type        = number
  validation {
    condition     = var.max_hours == floor(var.max_hours) && var.max_hours >= 1 && var.max_hours <= 48
    error_message = "max_hours must be a whole number from 1 to 48."
  }
}

variable "autorun" {
  description = "Run job_script unattended on the analysis host after setup (mt-job.service), then shut down. Off: the user data is unchanged."
  type        = bool
  default     = false
}

variable "job_bucket" {
  description = "autorun: the work bucket (code/<commit>.bundle in, results/<session>/ out)."
  type        = string
  default     = ""
}

variable "job_commit" {
  description = "autorun: full commit sha of the code bundle to run."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^([0-9a-f]{40})?$", var.job_commit))
    error_message = "job_commit must be a full 40-character lowercase sha (or empty)."
  }
}

variable "job_script" {
  description = "autorun: the job script, relative to the repository root."
  type        = string
  default     = "experiments/ml-compare/job.sh"
}
