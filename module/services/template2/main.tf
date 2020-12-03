# VPC
resource "aws_vpc" "vpc" {
  cidr_block                       = var.cidr_block
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "vpc-${var.ver}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "terra_igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "ig-${var.ver}"
  }
}

# subnet
resource "aws_subnet" "subnet123" {
  count                   = length(var.subnet_cidr_block)
  cidr_block              = element(var.subnet_cidr_block, count.index)
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-${count.index}-${var.ver}"
  }
}


# Route table: attach Internet Gateway
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.rt_cidr_block
    gateway_id = aws_internet_gateway.terra_igw.id
  }
  tags = {
    Name = "rt-${var.ver}"
  }
}

# Route table association with public subnets
resource "aws_route_table_association" "a" {
  count          = length(var.subnet_cidr_block)
  subnet_id      = element(aws_subnet.subnet123.*.id, count.index)
  route_table_id = aws_route_table.public_rt.id
}

# load balancer security group
resource "aws_security_group" "load_balancer" {
  name   = "lb_security_group"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security group - application
resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id



  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application-${var.ver}"
  }
}


# Security group ingress rule - application
resource "aws_security_group_rule" "sample" {
  count     = length(var.port)
  type      = "ingress"
  from_port = element(var.port, count.index)
  to_port   = element(var.port, count.index)
  protocol  = "tcp"
  #cidr_blocks       = [var.sg_rule_cidr_block]
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.load_balancer.id
}

# Security group ingress rule - application 3306 port
resource "aws_security_group_rule" "rule1" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = [var.mysql_cidr_block]
  security_group_id = aws_security_group.application.id
}

# Security group - database
resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
    cidr_blocks     = [var.mysql_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database-${var.ver}"
  }
}

# IAM policy
resource "aws_iam_policy" "policy" {
  name        = var.iam_name
  path        = var.iam_path
  description = "allow EC2 instances to perform S3 buckets"

  policy = var.iam_policy
}

resource "aws_iam_role" "role" {
  name = var.aws_iam_role_name

  assume_role_policy = var.iam_assume_role_policy
}

resource "aws_iam_policy_attachment" "attach" {
  name       = var.aws_iam_policy_attachment_name
  roles      = [aws_iam_role.role.name]
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "profile" {
  name = "ec2_profile"
  role = aws_iam_role.role1.name
}

# Start to create RDS
locals {
  resource_name_prefix = "${var.namespace}-${var.ver}"
}

resource "aws_db_subnet_group" "_" {
  name       = "${local.resource_name_prefix}-subnet-group"
  subnet_ids = [element(aws_subnet.subnet123.*.id, 1), element(aws_subnet.subnet123.*.id, 2)]
}

resource "aws_db_instance" "_" {
  identifier = "${local.resource_name_prefix}-${var.rds_identifier}"

  allocated_storage       = var.rds_allocated_storage
  backup_retention_period = var.rds_backup_retention_period
  backup_window           = var.rds_backup_window
  maintenance_window      = var.rds_maintenance_window
  db_subnet_group_name    = aws_db_subnet_group._.id
  engine                  = var.rds_engine
  engine_version          = var.rds_engine_version
  instance_class          = var.rds_instance_class
  multi_az                = var.multi_az
  name                    = var.rds_name
  username                = var.rds_username
  password                = var.password
  port                    = var.rds_port
  publicly_accessible     = var.rds_publicly_accessible
  storage_encrypted       = var.rds_storage_encrypted
  storage_type            = var.storage_type

  vpc_security_group_ids = [aws_security_group.database.id]

  allow_major_version_upgrade = false
  auto_minor_version_upgrade  = true

  final_snapshot_identifier = null
  snapshot_identifier       = ""
  skip_final_snapshot       = true

  performance_insights_enabled = false
}

resource "random_string" "password" {
  length  = 8
  special = false
}

# Start to create EC2
resource "aws_key_pair" "auth" {
  key_name   = var.ec2_key_name
  public_key = var.ec2_public_key
}
/*
data "aws_ami" "ami" {
  most_recent = var.ec2_aws_ami

  #filter {
  #  name   = "AMI Name"
  #  values = ["csye6225_*"]
  #}

  owners = [var.dev_account]
}
*/
resource "aws_iam_instance_profile" "instance_profile" {
  name = "jkfh"
  role = aws_iam_role.role1.name
}

/*
resource "aws_instance" "ubuntu" {
  ami = data.aws_ami.ami.id
  connection {
    # The default username for our AMI
    user = "ec2-user"
    host = "${aws_instance.ubuntu.public_ip}"
    # The connection will use the local SSH agent for authentication.
  }
  instance_type           = var.instance_type
  key_name                = "${aws_key_pair.auth.id}"
  vpc_security_group_ids  = [aws_security_group.application.id]
  subnet_id               = element(aws_subnet.subnet123.*.id, 3)
  disable_api_termination = var.ec2_disable_api_termination
  user_data               = <<-EOF
#!/bin/bash
echo DB_USERNAME="${var.DB_USERNAME}" >> /etc/environment
echo DB_PASSWORD="${var.DB_PASSWORD}" >> /etc/environment
echo DB_NAME="${var.DB_NAME}" >> /etc/environment
echo HOSTNAME="${aws_db_instance._.endpoint}" >> /etc/environment
echo BUCKET_NAME="${var.s3_bucket_name}" >> /etc/environment
  EOF

  iam_instance_profile = "${aws_iam_instance_profile.profile.name}"

  root_block_device {
    delete_on_termination = var.ec2_delete_on_termination
    volume_size           = var.ec2_volume_size
    volume_type           = var.ec2_volume_type
  }

  tags = {
    Name = "ubuntu"
  }
}*/

# create dynamodb
resource "aws_dynamodb_table" "table" {
  name           = var.dy_name
  hash_key       = var.dy_hash_key
  read_capacity  = var.dy_read_capacity
  write_capacity = var.dy_write_capacity

  attribute {
    name = var.dy_attribute_name
    type = var.dy_attribute_type
  }
}

# create s3
resource "aws_s3_bucket" "s3" {
  bucket        = var.s3_bucket_name
  force_destroy = var.s3_force_destroy
  acl           = var.s3_acl
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        #kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm = var.s3_sse_algorithm
      }
    }
  }

  lifecycle_rule {
    enabled = var.s3_lifecycle_enabled

    noncurrent_version_transition {
      days          = var.s3_days
      storage_class = var.s3_storage_class
    }
  }

  tags = {
    Name = var.s3_bucket_name
  }
}

# IAM role and policies
resource "aws_iam_policy" "policy2" {
  name = "GH-Upload-To-S3"
  path = "/"

  policy = <<EOF
{
  "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "policy3" {
  name = "GH-Code-Deploy"
  path = "/"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:us-east-1:931397163240:application:csye6225-webapp"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:us-east-1:931397163240:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:us-east-1:931397163240:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:us-east-1:931397163240:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "policy4" {
  name = "gh-ec2-ami"
  path = "/"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "user-attach2" {
  name       = "test-attachment2"
  users      = ["codedeploy"]
  policy_arn = aws_iam_policy.policy2.arn
}

resource "aws_iam_policy_attachment" "user-attach3" {
  name       = "test-attachment3"
  users      = ["codedeploy"]
  policy_arn = aws_iam_policy.policy3.arn
}

resource "aws_iam_policy_attachment" "user-attach4" {
  name       = "test-attachment4"
  users      = ["codedeploy"]
  policy_arn = aws_iam_policy.policy4.arn
}

resource "aws_iam_role_policy" "role-policy" {
  name = "CodeDeploy-EC2-S3"
  role = aws_iam_role.role1.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
      "Statement": [
          {
              "Action": [
                  "s3:Get*",
                  "s3:List*"
              ],
              "Effect": "Allow",
              "Resource": [
                "*",
                "*"
                ]
          },
          {
            "Action": [
                "s3:CreateBucket",
                "s3:ListBucket",
                "s3:DeleteBucket",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetObjectVersion",
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
                "s3:GetBucketAcl",
                "s3:PutBucketVersioning",
                "s3:GetBucketVersioning",
                "s3:PutLifecycleConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:DeleteBucketPolicy"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::webapp.chaoyi.yuan",
                "arn:aws:s3:::webapp.chaoyi.yuan/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:us-east-1:931397163240:fall2020"
        }
      ]
  }
  EOF
}


resource "aws_iam_role" "role1" {
  name = "CodeDeployEC2ServiceRole"
  #force_detach_policies = true

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}

resource "aws_iam_role" "role2" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "codedeploy.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
    EOF
}

resource "aws_iam_role_policy_attachment" "role-attach" {
  role       = aws_iam_role.role2.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}


# DNS Record
data "aws_route53_zone" "selected" {
  name         = "prod.martinyuan.me"
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "prod.martinyuan.me"
  type    = "A"
  #ttl     = "60"
  #records = [aws_instance.ubuntu.public_ip]

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
}

# Codedeploy application
resource "aws_codedeploy_app" "codedeploy-app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "codedeploy-group" {
  app_name               = aws_codedeploy_app.codedeploy-app.name
  deployment_group_name  = "csye6225-webapp-deployment"
  service_role_arn       = aws_iam_role.role2.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"

  deployment_style {
    deployment_type = "IN_PLACE"
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "ubuntu"
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

# load balancer
resource "aws_lb" "alb" {
  name               = "alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = aws_subnet.subnet123.*.id

  #enable_deletion_protection = true
}

resource "aws_lb_target_group" "lbtg" {
  name     = "tf-lb-tg"
  port     = 9090
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    path = "/hello"
    port = 9090
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"
  #ssl_policy        = "ELBSecurityPolicy-2016-08"
  #certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lbtg.arn
  }
}

data "aws_ami" "ami" {
  most_recent = var.ec2_aws_ami

  #filter {
  #  name   = "AMI Name"
  #  values = ["csye6225_*"]
  #}

  owners = [var.dev_account]
}

resource "aws_launch_configuration" "as_config" {
  name                        = "asg_launch_config"
  image_id                    = data.aws_ami.ami.id
  instance_type               = "t2.micro"
  key_name                    = "${aws_key_pair.auth.id}"
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
echo DB_USERNAME="${var.DB_USERNAME}" >> /etc/environment
echo DB_PASSWORD="${var.DB_PASSWORD}" >> /etc/environment
echo DB_NAME="${var.DB_NAME}" >> /etc/environment
echo HOSTNAME="${aws_db_instance._.endpoint}" >> /etc/environment
echo BUCKET_NAME="${var.s3_bucket_name}" >> /etc/environment
  EOF
  iam_instance_profile        = "${aws_iam_instance_profile.profile.name}"
  security_groups             = [aws_security_group.application.id]
}

resource "aws_autoscaling_group" "as_group" {
  name                      = "WebServerGroup"
  default_cooldown          = 60
  max_size                  = 5
  min_size                  = 3
  health_check_grace_period = 300
  health_check_type         = "EC2"
  desired_capacity          = 3
  launch_configuration      = aws_launch_configuration.as_config.name
  vpc_zone_identifier       = aws_subnet.subnet123.*.id

  tag {
    key                 = "Name"
    value               = "ubuntu"
    propagate_at_launch = true
  }
  target_group_arns = [aws_lb_target_group.lbtg.arn]
}

resource "aws_autoscaling_policy" "bat1" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.as_group.name
}

resource "aws_autoscaling_policy" "bat2" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.as_group.name
}

resource "aws_cloudwatch_metric_alarm" "bat3" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.as_group.name
  }

  alarm_description = "Scale-up if CPU > 5% for 1 minute"
  alarm_actions     = [aws_autoscaling_policy.bat1.arn]
}

resource "aws_cloudwatch_metric_alarm" "bat4" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.as_group.name
  }

  alarm_description = "Scale-up if CPU < 3% for 1 minute"
  alarm_actions     = [aws_autoscaling_policy.bat1.arn]
}

# Adding policy to new user named "serverless"
# Giving the permission to S3
resource "aws_iam_policy_attachment" "user-attach5" {
  name       = "test-attachment5"
  users      = ["serverless"]
  policy_arn = aws_iam_policy.policy2.arn
}

# This policy allows the aws cli to deploy the lambda
resource "aws_iam_policy" "policy5" {
  name = "Lambda-Deploy"

  policy = <<EOF
{
  "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionCode"
            ],
            "Resource": [
                "arn:aws:lambda:us-east-1:931397163240:function:lambda_function"
            ]
        }
    ]
}
EOF
}

# Adding the previous policy5 to user "serverless"
resource "aws_iam_policy_attachment" "user-attach6" {
  name       = "test-attachment6"
  users      = ["serverless"]
  policy_arn = aws_iam_policy.policy5.arn
}

# Creating SNS Topic
resource "aws_sns_topic" "user_updates" {
  name = "fall2020"
}

# lambda role
resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# three policies in lambda role
resource "aws_iam_policy" "lambda_policy" {
  name   = "lambda_policy"
  policy = <<EOF
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "dynamodb:*",
                  "ses:*",
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents"
              ],
              "Resource": "*"
          }
      ]
}
EOF
}

resource "aws_iam_policy_attachment" "ses_db_lambda_role" {
  name       = "ses_db_lambda_role"
  roles      = [aws_iam_role.iam_for_lambda.name]
  policy_arn = aws_iam_policy.lambda_policy.arn
}

resource "aws_lambda_function" "test_lambda" {
  #filename      = "lambda_function_payload.zip"
  s3_bucket     = "codedeploy.prod.martinyuan.me"
  s3_key        = "function.zip"
  function_name = "lambda_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "main"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  # source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "go1.x"
}

# Adding SNS trigger to lambda
resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowExxcutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "lambda_function"
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.user_updates.arn
}

# Adding sns subscription to lambda
resource "aws_sns_topic_subscription" "subscription" {
  topic_arn = aws_sns_topic.user_updates.arn
  protocol  = "LAMBDA"
  endpoint  = aws_lambda_function.test_lambda.arn
}
