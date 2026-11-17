# One-session AWS machine for the KAIROS + ORTHRUS (PIDSMaker 3.0.0)
# reproduction on DARPA THEIA-E3. The lab test host (15 GB RAM) ran out of
# memory in the batching stage, so the run moves here.
#
# What it creates: a VPC with one public subnet, a GPU machine with no open
# inbound ports (reached through an EC2 Instance Connect Endpoint), an S3
# bucket for the dump in and the results out, and an instance role that can
# only touch that bucket. Everything is tagged Project=MicroTRACE and is
# destroyed after the session:
#
#   terraform init && terraform plan
#   terraform apply                # only after the price is agreed
#   terraform destroy              # same session; also empties the bucket
#
# Cost cap: the machine shuts itself down after var.max_hours, and shutdown
# terminates it (the root disk goes with it), so copy results to S3 as you go.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile
  default_tags {
    tags = {
      Project = "MicroTRACE"
      Purpose = "pidsmaker-theia"
    }
  }
}

data "aws_caller_identity" "me" {}

# --- Network ---------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "mt-pidsmaker" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "mt-pidsmaker" }
}

# Public subnet only for outbound traffic (image build, conda, pip, S3).
# Nothing is reachable from the internet: the instance group admits SSH from
# the Instance Connect Endpoint and nothing else.
resource "aws_subnet" "this" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.77.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags                    = { Name = "mt-pidsmaker" }
}

resource "aws_route_table" "this" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "mt-pidsmaker" }
}

resource "aws_route_table_association" "this" {
  subnet_id      = aws_subnet.this.id
  route_table_id = aws_route_table.this.id
}

resource "aws_security_group" "eice" {
  name   = "mt-pidsmaker-eice"
  vpc_id = aws_vpc.this.id
}

resource "aws_security_group" "node" {
  name   = "mt-pidsmaker-node"
  vpc_id = aws_vpc.this.id
}

resource "aws_vpc_security_group_egress_rule" "eice_to_node" {
  security_group_id            = aws_security_group.eice.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

resource "aws_vpc_security_group_ingress_rule" "node_from_eice" {
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_security_group.eice.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

resource "aws_vpc_security_group_egress_rule" "node_out" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_ec2_instance_connect_endpoint" "this" {
  subnet_id          = aws_subnet.this.id
  security_group_ids = [aws_security_group.eice.id]
  preserve_client_ip = false
  tags               = { Name = "mt-pidsmaker" }
}

# --- Bucket: dump in, results out ----------------------------------------------

resource "aws_s3_bucket" "this" {
  bucket_prefix = "mt-pidsmaker-"
  force_destroy = true # destroy empties it; copy results down first
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# --- Instance role: this bucket only -------------------------------------------

resource "aws_iam_role" "node" {
  name_prefix = "MicroTRACE-pidsmaker-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "node_bucket" {
  name = "bucket-only"
  role = aws_iam_role.node.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.this.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.this.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "node" {
  name_prefix = "MicroTRACE-pidsmaker-"
  role        = aws_iam_role.node.name
}

# --- Machine -------------------------------------------------------------------

resource "aws_instance" "node" {
  ami                                  = var.ami_id
  instance_type                        = var.instance_type
  subnet_id                            = aws_subnet.this.id
  vpc_security_group_ids               = [aws_security_group.node.id]
  iam_instance_profile                 = aws_iam_instance_profile.node.name
  instance_initiated_shutdown_behavior = "terminate"

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.disk_gb
    throughput            = 500
    iops                  = 6000
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2 # containers may need instance credentials
  }

  # Cost cap only; the run itself is set up over SSH.
  user_data = <<-EOF
    #!/bin/bash
    systemd-run --unit=mt-cost-cap --on-active=${var.max_hours}h /sbin/shutdown -h now
  EOF

  tags = { Name = "mt-pidsmaker" }
}

# Second machine: the original ORTHRUS repo with the authors' pre-trained
# weights, to check our data and labels against their README results. Same
# network, role and bucket; created only with -var orthrus_node=true.
resource "aws_instance" "orthrus" {
  count                                = var.orthrus_node ? 1 : 0
  ami                                  = var.ami_id
  instance_type                        = var.orthrus_instance_type
  subnet_id                            = aws_subnet.this.id
  vpc_security_group_ids               = [aws_security_group.node.id]
  iam_instance_profile                 = aws_iam_instance_profile.node.name
  instance_initiated_shutdown_behavior = "terminate"

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 150
    throughput            = 250
    iops                  = 3000
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = <<-EOT
    #!/bin/bash
    systemd-run --unit=mt-cost-cap --on-active=${var.orthrus_max_hours}h /sbin/shutdown -h now
  EOT

  tags = { Name = "mt-orthrus-original" }
}
