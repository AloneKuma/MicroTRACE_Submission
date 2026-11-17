variable "aws_profile" {
  description = "CLI profile that assumes the MicroTRACE-Terraform role."
  type        = string
  default     = "microtrace"
}

variable "instance_type" {
  description = "g6.16xlarge (64 vCPU, 256 GB, 1x L4) for KAIROS with the chunked-flush patch: 193 GB RAM peak, GPU fits 24 GB (docs/plans/kairos-reproduction-plan.md). Fallback: g6.24xlarge (384 GB). ORTHRUS ran on g5.8xlarge (128 GB)."
  type        = string
  default     = "g6.16xlarge"
}

variable "availability_zone" {
  type    = string
  default = "us-east-1a"
}

variable "ami_id" {
  description = "Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 24.04) 20261016: NVIDIA driver, Docker, NVIDIA container toolkit."
  type        = string
  default     = "ami-0e56f571f15c88d23"
}

variable "disk_gb" {
  description = "Root disk. Host run used about 70 GB before training (image 16 GB, database 17 GB, artifacts 32 GB)."
  type        = number
  default     = 300
}

variable "orthrus_node" {
  description = "Second machine for the original ORTHRUS code with the authors' weights (inference only). Off unless set."
  type        = bool
  default     = false
}

variable "orthrus_instance_type" {
  description = "g5.8xlarge (32 vCPU, 128 GB, A10G 24 GB): ORTHRUS needed 71 GB in PIDSMaker and about 2 GB of GPU memory in its paper."
  type        = string
  default     = "g5.8xlarge"
}

variable "orthrus_max_hours" {
  description = "The ORTHRUS machine shuts down (and terminates) this many hours after boot."
  type        = number
  default     = 3
}

variable "max_hours" {
  description = "The machine shuts down (and terminates) this many hours after boot. 6 h covers KAIROS S1 + S1q."
  type        = number
  default     = 6
}
