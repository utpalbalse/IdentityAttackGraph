output "role_arn" {
  description = "ARN of the collector role. Pass to the collector via --role-arn."
  value       = aws_iam_role.collector.arn
}

output "role_name" {
  value = aws_iam_role.collector.name
}
