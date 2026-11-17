variable "aws_profile" {
  description = "CLI profile that assumes the MicroTRACE-Terraform role."
  type        = string
  default     = "microtrace"
}

variable "paper_user" {
  description = "IAM user that may assume the uploader role (the paper's CLI user)."
  type        = string
  default     = "microtrace-paper"
}

variable "lock_days" {
  description = "Object Lock default retention on the sealed bucket only (governance mode)."
  type        = number
  default     = 180
}

variable "ir_after_days" {
  description = "Days after upload before held-out data moves to Glacier Instant Retrieval (after the campaign)."
  type        = number
  default     = 60
}

variable "freeze_at" {
  description = "After this time no new object may be written under the sealed heldout/ prefix (RFC 3339). Set when the last batch is uploaded and frozen; the far-future default leaves uploads open."
  type        = string
  default     = "2026-11-13T09:03:12Z" # set when HELD_OUT and HELD_OUT-cases were frozen; do not move later
}
