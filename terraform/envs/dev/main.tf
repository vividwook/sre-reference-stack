terraform {
  required_version = "~> 1.8"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
  # For first run we’ll keep local state.
  # Later you can migrate to S3 + DynamoDB backend.
}

provider "aws" { region = var.region }

locals {
  name = "${var.name_prefix}-${var.env}"
  tags = {
    project    = var.name_prefix
    env        = var.env
    managed_by = "terraform"
  }
}

# ----------------
# Networking (VPC)
# ----------------

resource "aws_vpc" "this" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = merge(local.tags, { Name = "${local.name}-public-a" })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true
  tags = merge(local.tags, { Name = "${local.name}-public-b" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-rt-public" })
}

resource "aws_route" "public_to_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# -----------
# Security Groups
# -----------

resource "aws_security_group" "alb" {
  name   = "${local.name}-alb-sg"
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-alb-sg" })

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress { 
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name   = "${local.name}-app-sg"
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-app-sg" })

  ingress {
    description      = "app from alb"
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    security_groups  = [aws_security_group.alb.id]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ----
# ECR
# ----

resource "aws_ecr_repository" "app" {
  name                 = var.ecr_repo_name
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
  tags = merge(local.tags, { Name = "${local.name}-ecr" })
}

# ---------------
# IAM for EC2/ECR
# ---------------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  name               = "${local.name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "ec2_policy" {
  statement {
    sid     = "ECR"
    actions = ["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","ecr:GetRepositoryPolicy","ecr:DescribeRepositories","ecr:ListImages","ecr:DescribeImages"]
    resources = ["*"]
  }
  statement {
    sid     = "CWLogs"
    actions = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ec2_inline" {
  name   = "${local.name}-ec2-policy"
  policy = data.aws_iam_policy_document.ec2_policy.json
}

resource "aws_iam_role_policy_attachment" "ec2_attach" {
  role       = aws_iam_role.ec2.name
  policy_arn = aws_iam_policy.ec2_inline.arn
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${local.name}-ec2-profile"
  role = aws_iam_role.ec2.name
}

# -------
# ALB/TG
# -------

resource "aws_lb" "this" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags               = local.tags
}

resource "aws_lb_target_group" "app" {
  name     = "${local.name}-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.this.id
  health_check {
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }
  tags = local.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# -------------
# Compute (ASG)
# -------------

data "aws_ami" "al2" {
  owners      = ["137112412989"] # Amazon
  most_recent = true
  filter {
    name = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

locals {
  ecr_image = "${data.aws_caller_identity.me.account_id}.dkr.ecr.${var.region}.amazonaws.com/${var.ecr_repo_name}:main"
}

data "aws_caller_identity" "me" {}

# user data: install docker, auth to ECR, pull & run container
locals {
  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euxo pipefail
    yum update -y
    amazon-linux-extras install docker -y || yum install -y docker
    systemctl enable --now docker

    REGION="${var.region}"
    ECR_IMAGE="${local.ecr_image}"

    # login to ECR
    aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin $(echo "$ECR_IMAGE" | cut -d/ -f1)

    docker pull "$ECR_IMAGE"
    docker run -d --name app --restart unless-stopped -p 8080:8080 "$ECR_IMAGE"
  EOF
  )
}

resource "aws_launch_template" "app" {
  name_prefix   = "${local.name}-lt-"
  image_id      = data.aws_ami.al2.id
  instance_type = "t3.micro"
  iam_instance_profile { name = aws_iam_instance_profile.ec2.name }
  user_data = local.user_data
  network_interfaces {
    security_groups             = [aws_security_group.app.id]
    associate_public_ip_address = true
  }
  tag_specifications {
    resource_type = "instance"
    tags = merge(local.tags, { Name = "${local.name}-app" })
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${local.name}-asg"
  max_size                  = 2
  min_size                  = 1
  desired_capacity          = 1
  vpc_zone_identifier       = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  health_check_type         = "ELB"
  health_check_grace_period = 60

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.app.arn]

  tag {
    key                 = "Name"
    value               = "${local.name}-app"
    propagate_at_launch = true
  }
  lifecycle { create_before_destroy = true }
}

# ----------------
# CloudWatch Alarms
# ----------------

resource "aws_sns_topic" "alerts" {
  name = "${local.name}-alerts"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${local.name}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
  }
  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
  tags          = local.tags
}

# -------
# Output
# -------

output "alb_dns_name" { value = aws_lb.this.dns_name }
output "ecr_repo_url" { value = aws_ecr_repository.app.repository_url }
