variable "region" {
  type = string
}

variable "cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

variable "subnet_cidr_block" {
  type    = "list"
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "azs" {
  type    = "list"
  default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "ver" {
  type = string

}

variable "rt_cidr_block" {
  type    = string
  default = "0.0.0.0/0"
}

variable "port" {
  type    = "list"
  default = [22, 80, 443, 9090]
}

variable "sg_rule_cidr_block" {
  type    = string
  default = "0.0.0.0/0"
}

variable "mysql_cidr_block" {
  type    = string
  default = "10.0.0.0/24"
}

# EC2 variables
variable "ec2_key_name" {
  type    = string
  default = "csye6225_aws"
}

variable "ec2_public_key" {
  type    = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCp/vJSROhyhSE+nMAJa1XZaaWEKoLjIV4h8iMMCYanKLSzARZiseP4BoNV61/Y+z8g/XXYQJ1oC8S7HxoWTuItNfuA+6/7/eOQNWO2nlClXNx69Ei+RdtAx/gu7ODDNhnxZsnGz07gF5FGpQ3grEVPOgcWQoHioYP6g8UXp675Th75L9qtFYQFtYxUWIZdZezGpLX/6DjrwXScBuU7A7vbhDAi9TXkXd8q6wFS4+kXnnEp/o6+ImTbRCpQr69cEH5Ge50N91YXasSyQDMHfBzlU6vhNBpMOFc8ZRGjV1ZCUCkXg9obR7o62giJjE9r6/8XCMQJyBHP8VVFFmbyiTeK7c92Ev0k+cxrkhzeJoGagsKPovWufSS9drv31LafBd0AHine2nSuhhT8tjIdP6xJMjpPxPpFDc/WkNzyQOqSoWV3qAfKJgP16TpreDZeG0XGEumnGhrfM2YNZWopA+kXH1f2tlGaI7Crz6BaOpvR1Q/nHdSfHF946KAuymBwE+8= martin@chaoyi.local"
}

variable "ec2_aws_ami" {
  type    = bool
  default = true
}
variable "dev_account" {
  type    = string
  default = "041728207796"
}

variable "ec2_disable_api_termination" {
  type    = bool
  default = false
}

variable "ec2_delete_on_termination" {
  type    = bool
  default = true
}

variable "ec2_volume_size" {
  type    = number
  default = 20
}

variable "ec2_volume_type" {
  type    = string
  default = "gp2"
}

#variable "ami_key_pair_name" {}

# RDS variables
variable "DB_USERNAME" {
  type    = string
  default = "csye6225fall2020"
}

variable "DB_PASSWORD" {
  default = "Y940519a"
}

variable "DB_NAME" {
  default = "csye6225"
}

variable "namespace" {
  type    = string
  default = "csye6225-fall2020"
}

variable "ami" {
  type    = string
  default = "ami-0817d428a6fb68645"
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}

# RDS
variable "rds_identifier" {
  default = "csye6225-f20"
}

variable "rds_engine" {
  type    = string
  default = "mysql"
}

variable "rds_engine_version" {
  type    = string
  default = "8.0.15"
}

variable "rds_instance_class" {
  type    = string
  default = "db.t2.micro"
}

variable "rds_allocated_storage" {
  type    = number
  default = 10
}

variable "rds_storage_encrypted" {
  type    = bool
  default = false
}

variable "rds_name" {
  type    = string
  default = "csye6225"
}

variable "rds_username" {
  type    = string
  default = "csye6225fall2020"
}

variable "rds_port" {
  type    = number
  default = 3306
}
variable "rds_maintenance_window" {
  type    = string
  default = "Mon:00:00-Mon:03:00"
}
variable "rds_backup_window" {
  type    = string
  default = "10:46-11:16"
}
variable "rds_backup_retention_period" {
  type    = number
  default = 1
}
variable "rds_publicly_accessible" {
  type    = bool
  default = false
}
variable "rds_final_snapshot_identifier" {
  type    = string
  default = "prod-trademerch-website-db-snapshot"
}
variable "rds_snapshot_identifier" {
  type    = string
  default = null
}
variable "rds_performance_insights_enabled" {
  type    = bool
  default = true
}
variable "multi_az" {
  type    = bool
  default = false
}
variable "password" {
  type    = string
  default = "Y940519a"
}
variable "storage_type" {
  type    = string
  default = "gp2"
}

# dynamodb
variable "dy_name" {
  type    = string
  default = "csye6225"
}

variable "dy_hash_key" {
  type    = string
  default = "id"
}

variable "dy_read_capacity" {
  type    = number
  default = 2
}

variable "dy_write_capacity" {
  type    = number
  default = 2
}

variable "dy_attribute_name" {
  type    = string
  default = "id"
}

variable "dy_attribute_type" {
  type    = string
  default = "S"
}

# S3
variable "s3_bucket_name" {
  type    = string
  default = "webapp.chaoyi.yuan"
}

variable "s3_force_destroy" {
  type    = bool
  default = true
}

variable "s3_acl" {
  type    = string
  default = "private"
}

variable "s3_sse_algorithm" {
  type    = string
  default = "aws:kms"
}

variable "s3_lifecycle_enabled" {
  type    = bool
  default = true
}

variable "s3_days" {
  type    = number
  default = 30
}

variable "s3_storage_class" {
  type    = string
  default = "STANDARD_IA"
}

# IAM
variable "iam_name" {
  type    = string
  default = "WebAppS3"
}

variable "iam_path" {
  type    = string
  default = "/"
}

variable "iam_policy" {
  type    = string
  default = <<EOF
{"Version": "2012-10-17","Statement": [{"Action": ["s3:CreateBucket","s3:ListBucket","s3:DeleteBucket","s3:GetBucketLocation","s3:GetObject","s3:PutObject","s3:DeleteObject","s3:GetObjectVersion","s3:GetBucketPolicy","s3:PutBucketPolicy","s3:GetBucketAcl","s3:PutBucketVersioning","s3:GetBucketVersioning","s3:PutLifecycleConfiguration","s3:GetLifecycleConfiguration","s3:DeleteBucketPolicy"],"Effect": "Allow","Resource": ["arn:aws:s3:::webapp.chaoyi.yuan","arn:aws:s3:::webapp.chaoyi.yuan/*"]}]}
EOF
}

variable "aws_iam_role_name" {
  type    = string
  default = "EC2-CSYE6225"
}

variable "iam_assume_role_policy" {
  type    = string
  default = <<EOF
{"Version": "2012-10-17","Statement": [{"Action": "sts:AssumeRole","Principal": {"Service": "ec2.amazonaws.com"},"Effect": "Allow","Sid": ""}]}
EOF
}

variable "aws_iam_policy_attachment_name" {
  type    = string
  default = "attachment"
}
