variable "region" { 
    type = string
    default = "us-east-2"
}
variable "name_prefix" {
    type = string
    default = "sre-ref"
}
variable "env" {
    type = string
    default = "dev"
}
variable "alarm_email" {
    type = string
}
variable "ecr_repo_name" {
    type = string
    default = "resume-app"
}
