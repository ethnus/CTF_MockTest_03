provider "aws" {
  region = var.region
}

# --------------------------
# Inputs
# --------------------------
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "prefix" {
  description = "Challenge ID prefix (used in names/tags)"
  type        = string
  default     = "ethnus-mocktest-01"
}

# --------------------------
# Identity + random suffix
# --------------------------
data "aws_caller_identity" "me" {}

resource "random_id" "rand" {
  byte_length = 4
}

locals {
  account_id = data.aws_caller_identity.me.account_id
  suffix_dec = random_id.rand.dec
  common_tags = {
    Owner     = "Ethnus"
    Challenge = var.prefix
  }
  vpc_a_cidr = "10.10.0.0/16"
  vpc_b_cidr = "10.20.0.0/16"
}

# --------------------------
# KMS for data encryption
# --------------------------
resource "aws_kms_key" "cmk" {
  description             = "${var.prefix}-cmk"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "cmk_alias" {
  name          = "alias/${var.prefix}-cmk"
  target_key_id = aws_kms_key.cmk.key_id
}

# --------------------------
# S3 data bucket (SSE-KMS)
# --------------------------
resource "aws_s3_bucket" "data_bucket" {
  bucket        = "${var.prefix}-${local.account_id}-${local.suffix_dec}-data"
  force_destroy = true
  # Intentionally missing tags for challenge
  # tags          = local.common_tags
}

resource "aws_s3_bucket_versioning" "data_ver" {
  bucket = aws_s3_bucket.data_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}

# (Optional) Block non-SSL access
resource "aws_s3_bucket_policy" "data_policy" {
  bucket = aws_s3_bucket.data_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.data_bucket.arn,
          "${aws_s3_bucket.data_bucket.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# --------------------------
# DynamoDB (SSE-KMS, On-Demand)
# --------------------------
resource "aws_dynamodb_table" "orders" {
  name         = "${var.prefix}-orders"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "pk"
  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }

  # Intentionally missing tags for challenge
  # tags = local.common_tags
}

# --------------------------
# VPC A (app) & VPC B (peer)
# --------------------------
resource "aws_vpc" "vpc_a" {
  cidr_block           = local.vpc_a_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.common_tags, { Name = "${var.prefix}-vpc-a" })
}

resource "aws_vpc" "vpc_b" {
  cidr_block           = local.vpc_b_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.common_tags, { Name = "${var.prefix}-vpc-b" })
}

resource "aws_subnet" "a_az1" {
  vpc_id                  = aws_vpc.vpc_a.id
  cidr_block              = cidrsubnet(local.vpc_a_cidr, 8, 1) # 10.10.1.0/24
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "${var.prefix}-a-az1" })
}

resource "aws_subnet" "a_az2" {
  vpc_id                  = aws_vpc.vpc_a.id
  cidr_block              = cidrsubnet(local.vpc_a_cidr, 8, 2) # 10.10.2.0/24
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "${var.prefix}-a-az2" })
}

resource "aws_subnet" "b_az1" {
  vpc_id                  = aws_vpc.vpc_b.id
  cidr_block              = cidrsubnet(local.vpc_b_cidr, 8, 1) # 10.20.1.0/24
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "${var.prefix}-b-az1" })
}

resource "aws_subnet" "b_az2" {
  vpc_id                  = aws_vpc.vpc_b.id
  cidr_block              = cidrsubnet(local.vpc_b_cidr, 8, 2) # 10.20.2.0/24
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "${var.prefix}-b-az2" })
}

# Manage main route tables so we can attach gateway endpoints to them
resource "aws_default_route_table" "rtb_a_main" {
  default_route_table_id = aws_vpc.vpc_a.default_route_table_id
  tags                   = merge(local.common_tags, { Name = "${var.prefix}-a-rtb-main" })
}

resource "aws_default_route_table" "rtb_b_main" {
  default_route_table_id = aws_vpc.vpc_b.default_route_table_id
  tags                   = merge(local.common_tags, { Name = "${var.prefix}-b-rtb-main" })
}

# VPC peering + routes on the main RTBs
resource "aws_vpc_peering_connection" "a_to_b" {
  vpc_id      = aws_vpc.vpc_a.id
  peer_vpc_id = aws_vpc.vpc_b.id
  auto_accept = true
  tags        = merge(local.common_tags, { Name = "${var.prefix}-pcx-a-b" })
}

resource "aws_route" "a_to_b" {
  route_table_id            = aws_default_route_table.rtb_a_main.id
  destination_cidr_block    = aws_vpc.vpc_b.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.a_to_b.id
}

resource "aws_route" "b_to_a" {
  route_table_id            = aws_default_route_table.rtb_b_main.id
  destination_cidr_block    = aws_vpc.vpc_a.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.a_to_b.id
}

# --------------------------
# VPC endpoints in VPC A
# --------------------------

# Gateway endpoints must be associated with a route table (use VPC A main RT)
resource "aws_vpc_endpoint" "s3_gw" {
  vpc_id            = aws_vpc.vpc_a.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  # Intentionally missing route table association for challenge
  # route_table_ids   = [aws_default_route_table.rtb_a_main.id]
  tags = merge(local.common_tags, { Name = "${var.prefix}-vpce-s3" })
}

resource "aws_vpc_endpoint" "ddb_gw" {
  vpc_id            = aws_vpc.vpc_a.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  # Intentionally missing route table association for challenge
  # route_table_ids   = [aws_default_route_table.rtb_a_main.id]

  # Intentionally restrictive policy that blocks PutItem for challenge
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "dynamodb:BatchGetItem",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable"
        # Missing: "dynamodb:PutItem", "dynamodb:BatchWriteItem", "dynamodb:UpdateItem"
      ]
      Resource = "*"
    }]
  })

  tags = merge(local.common_tags, { Name = "${var.prefix}-vpce-ddb" })
}

# Security group for Interface endpoints (and later Lambda ENIs if needed)
resource "aws_security_group" "vpce_sg" {
  name        = "${var.prefix}-vpce-sg"
  description = "Interface endpoint SG"
  vpc_id      = aws_vpc.vpc_a.id

  # Allow all VPC internal traffic to endpoints (simplified)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.vpc_a.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.prefix}-vpce-sg" })
}

# Interface endpoint for API Gateway (execute-api)
resource "aws_vpc_endpoint" "execute_api_if" {
  vpc_id              = aws_vpc.vpc_a.id
  service_name        = "com.amazonaws.${var.region}.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.a_az1.id, aws_subnet.a_az2.id]
  security_group_ids  = [aws_security_group.vpce_sg.id]
  private_dns_enabled = true
  tags                = merge(local.common_tags, { Name = "${var.prefix}-vpce-execapi" })
}

# (Optional) Add KMS/SNS Interface endpoints if you later require private access from ENIs
# resource "aws_vpc_endpoint" "kms_if" { ... }
# resource "aws_vpc_endpoint" "sns_if" { ... }

# --------------------------
# SNS and EventBridge
# --------------------------
resource "aws_sns_topic" "topic" {
  name = "${var.prefix}-topic"
  tags = local.common_tags
}

# Intentionally restrictive policy that denies publishing for challenge
resource "aws_sns_topic_policy" "topic_policy" {
  arn = aws_sns_topic.topic.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublish"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["sns:Publish"]
        Resource  = aws_sns_topic.topic.arn
      },
      {
        Sid       = "AllowOtherActions"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "sns:GetTopicAttributes",
          "sns:ListSubscriptionsByTopic",
          "sns:Subscribe"
        ]
        Resource = aws_sns_topic.topic.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "tick" {
  name                = "${var.prefix}-tick"
  description         = "challenge scheduler (disabled by default)"
  schedule_expression = "rate(5 minutes)"
  state               = "DISABLED" # replaces deprecated is_enabled
  tags                = local.common_tags
}

# --------------------------
# Lambda Functions
# --------------------------

# Lambda execution role (using LabRole if available, or create minimal role)
data "aws_iam_role" "labrole" {
  name = "LabRole"
}

# Lambda function packages
data "archive_file" "writer_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/writer/writer.py"
  output_path = "${path.module}/lambda/writer.zip"
}

data "archive_file" "reader_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/reader/reader.py"
  output_path = "${path.module}/lambda/reader.zip"
}

# Encrypt a flag for the reader function
resource "aws_kms_ciphertext" "flag" {
  key_id    = aws_kms_key.cmk.key_id
  plaintext = "ETHNUS{w3ll_4rch1t3ct3d_cl0ud_s3cur1ty_2025}"
}

# Writer Lambda Function
resource "aws_lambda_function" "writer" {
  filename         = data.archive_file.writer_zip.output_path
  function_name    = "${var.prefix}-writer"
  role             = data.aws_iam_role.labrole.arn
  handler          = "writer.handler"
  runtime          = "python3.9"
  timeout          = 30
  memory_size      = 128
  source_code_hash = data.archive_file.writer_zip.output_base64sha256

  # Intentionally misconfigured for the challenge
  reserved_concurrent_executions = 0 # This will cause the concurrency check to fail

  environment {
    variables = {
      DDB_TABLE = "wrong-table-name" # Intentionally wrong for challenge
      BUCKET    = aws_s3_bucket.data_bucket.bucket
      TOPIC_ARN = aws_sns_topic.topic.arn
    }
  }

  tags = local.common_tags
}

# Reader Lambda Function
resource "aws_lambda_function" "reader" {
  filename         = data.archive_file.reader_zip.output_path
  function_name    = "${var.prefix}-reader"
  role             = data.aws_iam_role.labrole.arn
  handler          = "reader.handler"
  runtime          = "python3.9"
  timeout          = 30
  memory_size      = 128
  source_code_hash = data.archive_file.reader_zip.output_base64sha256

  environment {
    variables = {
      DDB_TABLE           = aws_dynamodb_table.orders.name
      FLAG_CIPHERTEXT_B64 = aws_kms_ciphertext.flag.ciphertext_blob
    }
  }

  tags = local.common_tags
}

# EventBridge target for writer function
resource "aws_cloudwatch_event_target" "writer_target" {
  rule      = aws_cloudwatch_event_rule.tick.name
  target_id = "WriterTarget"
  arn       = aws_lambda_function.writer.arn
}

# Permission for EventBridge to invoke writer
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.writer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tick.arn
}

# --------------------------
# API Gateway (Private)
# --------------------------
resource "aws_api_gateway_rest_api" "api" {
  name        = "${var.prefix}-api"
  description = "Private API for challenge"

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [aws_vpc_endpoint.execute_api_if.id]
  }

  # Intentionally misconfigured policy for challenge
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "execute-api:Invoke"
      Resource  = "*"
      # Missing VPC endpoint condition - this makes the challenge
    }]
  })

  tags = local.common_tags
}

# API Gateway /orders resource
resource "aws_api_gateway_resource" "orders" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "orders"
}

# API Gateway GET method for /orders
resource "aws_api_gateway_method" "orders_get" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "GET"
  authorization = "NONE"
}

# API Gateway integration with Lambda reader
resource "aws_api_gateway_integration" "orders_lambda" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.orders_get.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  # Intentionally wrong Lambda function for challenge
  uri = aws_lambda_function.writer.invoke_arn # Should be reader!
}

# Permission for API Gateway to invoke Lambda reader
resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.writer.function_name # Wrong function!
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

# API Gateway deployment
resource "aws_api_gateway_deployment" "api_deployment" {
  depends_on = [
    aws_api_gateway_method.orders_get,
    aws_api_gateway_integration.orders_lambda
  ]

  rest_api_id = aws_api_gateway_rest_api.api.id

  # Force redeployment on any change
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_rest_api.api.body,
      aws_api_gateway_resource.orders.id,
      aws_api_gateway_method.orders_get.id,
      aws_api_gateway_integration.orders_lambda.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# API Gateway stage
resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.api.id
  stage_name    = "prod"
}

# --------------------------
# (Optional) Data source for LabRole (if you later attach to Lambda)
# --------------------------
# data "aws_iam_role" "labrole" {
#   name = "LabRole"
# }

# --------------------------
# Outputs
# --------------------------
output "prefix" { value = var.prefix }
output "account_id" { value = local.account_id }
output "region" { value = var.region }

output "kms_key_id" { value = aws_kms_key.cmk.key_id }
output "kms_alias" { value = aws_kms_alias.cmk_alias.name }

output "s3_bucket_name" { value = aws_s3_bucket.data_bucket.bucket }
output "dynamodb_table" { value = aws_dynamodb_table.orders.name }

output "vpc_a_id" { value = aws_vpc.vpc_a.id }
output "vpc_b_id" { value = aws_vpc.vpc_b.id }
output "subnets_vpc_a" { value = [aws_subnet.a_az1.id, aws_subnet.a_az2.id] }
output "subnets_vpc_b" { value = [aws_subnet.b_az1.id, aws_subnet.b_az2.id] }
output "rtb_a_main_id" { value = aws_default_route_table.rtb_a_main.id }
output "rtb_b_main_id" { value = aws_default_route_table.rtb_b_main.id }
output "pcx_id" { value = aws_vpc_peering_connection.a_to_b.id }

output "vpce_s3_id" { value = aws_vpc_endpoint.s3_gw.id }
output "vpce_ddb_id" { value = aws_vpc_endpoint.ddb_gw.id }
output "vpce_execute_id" { value = aws_vpc_endpoint.execute_api_if.id }

output "sns_topic_arn" { value = aws_sns_topic.topic.arn }
output "event_rule_name" { value = aws_cloudwatch_event_rule.tick.name }

# Summary output for deploy script
output "summary" {
  value = {
    prefix        = var.prefix
    region        = var.region
    account_id    = local.account_id
    s3_bucket     = aws_s3_bucket.data_bucket.bucket
    ddb_table     = aws_dynamodb_table.orders.name
    lambda_writer = aws_lambda_function.writer.function_name
    lambda_reader = aws_lambda_function.reader.function_name
    api_gateway   = aws_api_gateway_rest_api.api.id
    kms_key       = aws_kms_key.cmk.key_id
    vpc_a_id      = aws_vpc.vpc_a.id
    vpc_b_id      = aws_vpc.vpc_b.id
    sns_topic     = aws_sns_topic.topic.arn
  }
}
