# Permanent storage for the held-out campaign (decisions 2026-11-11, docs/plans/heldout-aws-plan.md).
# Separate from every per-session stack, so `terraform destroy` of a session never touches it.
# Back up this stack's terraform.tfstate outside the repo after every apply (losing it leaves
# the buckets unmanaged); both buckets also carry prevent_destroy.
#
# Two buckets, so that only held-out data is locked:
#   sealed  mt-sealed-*   Object Lock (governance, default var.lock_days), versioned
#     heldout/runs/<set>/<run>/              held-out runs WITHOUT restricted/ (what every system reads)
#     heldout/truth/<set>/<run>/restricted/  their truth: only the scoring role may read it
#   work    mt-work-*     versioned, no lock
#     dev/pilot-fit/<run>/   PILOT FIT runs, training data for KAIROS and ORTHRUS (development truth allowed)
#     archive/               old development data moved off the test host (Glacier Deep Archive)
#     results/<session>/     detection outputs of the analysis and baseline sessions (no truth)
#     scored/<date>/         scores (built from truth): written and read by the scoring role only
#     code/<commit>.bundle   the code each session runs (git bundle, put by the Terraform role)
#     cloudtrail/            audit log of every access to the sealed bucket (CloudTrail data events)
# A governance-mode lock still lets a principal with s3:BypassGovernanceRetention remove
# objects at the final teardown after the paper.
#
# Roles (short-lived credentials, never stored keys):
#   uploader  the test host: put into sealed heldout/, work dev/ and archive/; no reads, no deletes
#   analysis  session machines: read sealed heldout/runs/ and work dev/ + results/; write work results/
#   scoring   the single scoring step: analysis rights plus sealed heldout/truth/
#
# No budget alert (user's choice, 2026-10-08, confirmed 2026-11-11): every session is priced
# and approved first, and every machine has a hard cost cap (session stack max_hours).
#
#   terraform init && terraform plan
#   terraform apply ...   # only after the price is agreed (storage only, see the plan)

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
      Purpose = "heldout-storage"
    }
  }
}

data "aws_caller_identity" "me" {}

locals {
  account = data.aws_caller_identity.me.account_id
  # Only the paper's own IAM user may assume the uploader role (the account is shared).
  # Assumed directly (profile microtrace-base), not chained through MicroTRACE-Terraform,
  # so a session can last 12 h; a chained session is capped at 1 h.
  me      = "arn:aws:iam::${local.account}:user/${var.paper_user}"
  buckets = { sealed = aws_s3_bucket.sealed, work = aws_s3_bucket.work }
}

# --- Buckets -----------------------------------------------------------------------

resource "aws_s3_bucket" "sealed" {
  bucket_prefix       = "mt-sealed-"
  object_lock_enabled = true
  force_destroy       = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "work" {
  bucket_prefix = "mt-work-"
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.buckets
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled" # required by Object Lock on sealed; protects results on work
  }
}

resource "aws_s3_bucket_object_lock_configuration" "sealed" {
  bucket = aws_s3_bucket.sealed.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.lock_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.buckets
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = local.buckets
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.buckets
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Sealed data moves to Glacier Instant Retrieval (millisecond reads, $0.03/GB to read)
# once the campaign is expected to be over; a locked object may still change class.
resource "aws_s3_bucket_lifecycle_configuration" "sealed" {
  bucket = aws_s3_bucket.sealed.id
  rule {
    id     = "heldout-to-glacier-ir"
    status = "Enabled"
    filter {
      prefix = "heldout/"
    }
    transition {
      days          = var.ir_after_days
      storage_class = "GLACIER_IR"
    }
  }
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "work" {
  bucket = aws_s3_bucket.work.id
  rule {
    id     = "archive-to-deep-archive"
    status = "Enabled"
    filter {
      prefix = "archive/"
    }
    transition {
      days          = 0
      storage_class = "DEEP_ARCHIVE"
    }
  }
  rule {
    id     = "old-result-versions"
    status = "Enabled"
    filter {
      prefix = "results/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 7 # STATUS files are rewritten every 15 min
    }
  }
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}

# Truth is sealed: every principal except the scoring role is denied reads of heldout/truth/.
# (Teardown deletes need s3:DeleteObject* and s3:BypassGovernanceRetention, not reads.)
resource "aws_s3_bucket_policy" "sealed" {
  bucket = aws_s3_bucket.sealed.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SealTruth"
        Effect    = "Deny"
        Principal = "*"
        Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes",
          "s3:GetObjectTorrent", "s3:GetObjectVersionTorrent", "s3:GetObjectVersionForReplication",
        "s3:RestoreObject"]
        Resource = "${aws_s3_bucket.sealed.arn}/heldout/truth/*"
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = aws_iam_role.scoring.arn }
        }
      },
      {
        # Nothing held-out is ever deleted or hidden by a delete marker during the campaign
        # (lift this statement at the final teardown).
        Sid       = "NoDeletes"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"]
        Resource  = "${aws_s3_bucket.sealed.arn}/heldout/*"
      },
      {
        # Write-lock after the freeze: no new object (no replacement version) under heldout/
        # once var.freeze_at has passed. Set freeze_at when the last batch is uploaded.
        Sid       = "WriteLockAfterFreeze"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource  = "${aws_s3_bucket.sealed.arn}/heldout/*"
        Condition = { DateGreaterThan = { "aws:CurrentTime" = var.freeze_at } }
      },
      {
        Sid       = "TLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.sealed.arn, "${aws_s3_bucket.sealed.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "work" {
  bucket = aws_s3_bucket.work.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.work.arn, "${aws_s3_bucket.work.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # Scores are built from truth: no analysis session may read them.
        Sid       = "ScoredOnlyForScoring"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = "${aws_s3_bucket.work.arn}/scored/*"
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = [aws_iam_role.scoring.arn,
          "arn:aws:iam::${local.account}:role/MicroTRACE-Terraform"] }
        }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.work.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.work.arn}/cloudtrail/AWSLogs/${local.account}/*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn, "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

# --- Audit log: every read and write on the sealed bucket ---------------------------
# Evidence for the paper that no truth object was read before the scoring step.
locals {
  trail_name = "MicroTRACE-heldout-sealed-access"
  trail_arn  = "arn:aws:cloudtrail:us-east-1:${local.account}:trail/${local.trail_name}"
}

resource "aws_cloudtrail" "sealed" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.work.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = true # digest files prove the log was not edited

  advanced_event_selector {
    name = "sealed-bucket-data-events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.sealed.arn}/"]
    }
  }
  advanced_event_selector {
    name = "management-events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  depends_on = [aws_s3_bucket_policy.work]
}

# --- Roles -----------------------------------------------------------------------

resource "aws_iam_role" "uploader" {
  name                 = "MicroTRACE-heldout-uploader"
  max_session_duration = 43200 # 12 h: one build batch
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = local.me }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "uploader" {
  name = "put-only"
  role = aws_iam_role.uploader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.sealed.arn, aws_s3_bucket.work.arn] },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = [
          "${aws_s3_bucket.sealed.arn}/heldout/*",
          "${aws_s3_bucket.work.arn}/dev/*",
          "${aws_s3_bucket.work.arn}/archive/*",
        ]
      }
    ]
  })
}

locals {
  read_common = [
    "${aws_s3_bucket.sealed.arn}/heldout/runs/*",
    "${aws_s3_bucket.work.arn}/dev/*",
    "${aws_s3_bucket.work.arn}/results/*",
    "${aws_s3_bucket.work.arn}/code/*",
  ]
  ec2_trust = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role" "analysis" {
  name               = "MicroTRACE-heldout-analysis"
  assume_role_policy = local.ec2_trust
}

resource "aws_iam_role_policy" "analysis" {
  name = "runs-in-results-out"
  role = aws_iam_role.analysis.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.sealed.arn, aws_s3_bucket.work.arn] },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = local.read_common },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = "${aws_s3_bucket.work.arn}/results/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "analysis" {
  name = "MicroTRACE-heldout-analysis"
  role = aws_iam_role.analysis.name
}

# The single scoring step after the freeze: the analysis rights plus truth reads.
resource "aws_iam_role" "scoring" {
  name               = "MicroTRACE-heldout-scoring"
  assume_role_policy = local.ec2_trust
}

resource "aws_iam_role_policy" "scoring" {
  name = "runs-truth-in-results-out"
  role = aws_iam_role.scoring.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.sealed.arn, aws_s3_bucket.work.arn] },
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = concat(local.read_common, ["${aws_s3_bucket.sealed.arn}/heldout/truth/*",
        "${aws_s3_bucket.work.arn}/scored/*"])
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = ["${aws_s3_bucket.work.arn}/results/*", "${aws_s3_bucket.work.arn}/scored/*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "scoring" {
  name = "MicroTRACE-heldout-scoring"
  role = aws_iam_role.scoring.name
}
