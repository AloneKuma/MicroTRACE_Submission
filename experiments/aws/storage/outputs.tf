output "sealed_bucket" {
  description = "HELDOUT_BUCKET in the scripts: heldout/runs/ and heldout/truth/ (locked)."
  value       = aws_s3_bucket.sealed.id
}

output "work_bucket" {
  description = "BUCKET in the scripts: dev/, archive/, results/."
  value       = aws_s3_bucket.work.id
}

output "uploader_role_arn" {
  description = "aws sts assume-role --profile microtrace-base --role-arn <this> --duration-seconds 43200 --role-session-name host-batch-N (from the laptop; pass the temporary keys to the test host)"
  value       = aws_iam_role.uploader.arn
}

output "analysis_instance_profile" {
  value = aws_iam_instance_profile.analysis.name
}

output "scoring_instance_profile" {
  value = aws_iam_instance_profile.scoring.name
}
