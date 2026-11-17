output "instance_id" {
  value = aws_instance.node.id
}

output "bucket" {
  value = aws_s3_bucket.this.bucket
}

output "ssh" {
  description = "Connect through the Instance Connect Endpoint (pushes a one-time key)."
  value       = "aws ec2-instance-connect ssh --profile ${var.aws_profile} --region us-east-1 --instance-id ${aws_instance.node.id} --os-user ubuntu --connection-type eice"
}

output "orthrus_instance_id" {
  value = var.orthrus_node ? aws_instance.orthrus[0].id : null
}
