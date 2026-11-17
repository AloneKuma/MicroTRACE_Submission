output "analysis_id" {
  value = aws_instance.analysis.id
}

output "analysis_private_ip" {
  value = aws_instance.analysis.private_ip
}

output "sender_ids" {
  value = aws_instance.sender[*].id
}

output "kind_id" {
  value = aws_instance.kind[*].id
}

output "connect" {
  description = "aws ec2-instance-connect ssh --connection-type eice --instance-id <id> --os-user ubuntu (pushes a one-time key; tunnels last 1 h, so run jobs under nohup)"
  value       = aws_ec2_instance_connect_endpoint.this.id
}
