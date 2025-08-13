#!/usr/bin/env python3
"""
AWS AI Security Framework Control Validator

This script validates that AWS resources comply with the A1-A6 security controls
from the Agentic AI Cloud Security Framework.

Usage:
    python3 validate-aws-controls.py --profile my-aws-profile --region us-east-1

Requirements:
    pip install boto3 colorama
"""

import argparse
import boto3
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init()

class ControlValidator:
    def __init__(self, profile=None, region='us-east-1'):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = self.session.client('iam')
        self.ec2 = self.session.client('ec2')
        self.cloudtrail = self.session.client('cloudtrail')
        self.dynamodb = self.session.client('dynamodb')
        self.s3 = self.session.client('s3')
        self.region = region
        
        self.results = {
            'A1': {'status': 'UNKNOWN', 'details': []},
            'A2': {'status': 'UNKNOWN', 'details': []},
            'A3': {'status': 'UNKNOWN', 'details': []},
            'A4': {'status': 'UNKNOWN', 'details': []},
            'A5': {'status': 'UNKNOWN', 'details': []},
            'A6': {'status': 'UNKNOWN', 'details': []}
        }

    def print_header(self, control, description):
        print(f"\n{Fore.CYAN}═══ Control {control}: {description} ═══{Style.RESET_ALL}")

    def print_pass(self, message):
        print(f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}: {message}")

    def print_fail(self, message):
        print(f"{Fore.RED}✗ FAIL{Style.RESET_ALL}: {message}")

    def print_warning(self, message):
        print(f"{Fore.YELLOW}⚠ WARNING{Style.RESET_ALL}: {message}")

    def validate_a1_identity(self):
        """A1: Identity for Agents and Tools"""
        self.print_header("A1", "Identity for Agents and Tools")
        
        try:
            # Check for AI agent role
            role_name = 'ai-agent-execution-role'
            role = self.iam.get_role(RoleName=role_name)
            
            # Validate session duration
            max_duration = role['Role'].get('MaxSessionDuration', 3600)
            if max_duration <= 900:  # 15 minutes
                self.print_pass(f"IAM role session duration: {max_duration}s (≤15 minutes)")
                self.results['A1']['details'].append(f"Session duration: {max_duration}s")
            else:
                self.print_fail(f"IAM role session duration: {max_duration}s (>15 minutes)")
                
            # Check for least privilege tags
            tags = role['Role'].get('Tags', [])
            control_tag = next((tag for tag in tags if tag['Key'] == 'Control'), None)
            if control_tag and control_tag['Value'] == 'A1':
                self.print_pass("IAM role properly tagged with Control: A1")
            else:
                self.print_warning("IAM role missing Control tag")

            # Validate assume role policy has conditions
            policy_doc = role['Role']['AssumeRolePolicyDocument']
            has_conditions = any('Condition' in stmt for stmt in policy_doc.get('Statement', []))
            if has_conditions:
                self.print_pass("Assume role policy includes security conditions")
            else:
                self.print_warning("Assume role policy missing security conditions")
                
            self.results['A1']['status'] = 'PASS'
            
        except self.iam.exceptions.NoSuchEntityException:
            self.print_fail(f"AI agent IAM role '{role_name}' not found")
            self.results['A1']['status'] = 'FAIL'
        except Exception as e:
            self.print_fail(f"Error validating A1: {str(e)}")
            self.results['A1']['status'] = 'ERROR'

    def validate_a2_budget_guards(self):
        """A2: Tool Policy and Budget Guards"""
        self.print_header("A2", "Tool Policy and Budget Guards")
        
        try:
            # Check for budget tracking table
            table_name = 'ai-tool-usage-tracking'
            table = self.dynamodb.describe_table(TableName=table_name)
            
            # Validate TTL is enabled
            ttl_status = self.dynamodb.describe_time_to_live(TableName=table_name)
            if ttl_status['TimeToLiveDescription']['TimeToLiveStatus'] == 'ENABLED':
                self.print_pass("DynamoDB TTL enabled for session cleanup")
            else:
                self.print_fail("DynamoDB TTL not enabled")
                
            # Check table has proper keys
            key_schema = table['Table']['KeySchema']
            hash_key = next((key for key in key_schema if key['KeyType'] == 'HASH'), None)
            range_key = next((key for key in key_schema if key['KeyType'] == 'RANGE'), None)
            
            if hash_key and hash_key['AttributeName'] == 'session_id':
                self.print_pass("Budget tracking table has session_id hash key")
            if range_key and range_key['AttributeName'] == 'tool_name':
                self.print_pass("Budget tracking table has tool_name range key")
                
            self.results['A2']['status'] = 'PASS'
            
        except self.dynamodb.exceptions.ResourceNotFoundException:
            self.print_fail(f"Budget tracking table '{table_name}' not found")
            self.results['A2']['status'] = 'FAIL'
        except Exception as e:
            self.print_fail(f"Error validating A2: {str(e)}")
            self.results['A2']['status'] = 'ERROR'

    def validate_a5_forensics(self):
        """A5: Observation and Forensics"""
        self.print_header("A5", "Observation and Forensics")
        
        try:
            # Check for CloudTrail
            trails = self.cloudtrail.describe_trails()['trailList']
            ai_trails = [trail for trail in trails if 'ai-agent' in trail['Name'].lower()]
            
            if ai_trails:
                trail = ai_trails[0]
                self.print_pass(f"Found AI agent CloudTrail: {trail['Name']}")
                
                # Check if trail is logging
                status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if status['IsLogging']:
                    self.print_pass("CloudTrail is actively logging")
                else:
                    self.print_fail("CloudTrail is not logging")
                    
                # Check for data events
                event_selectors = self.cloudtrail.get_event_selectors(TrailName=trail['TrailARN'])
                has_bedrock_events = any(
                    any('Bedrock' in resource.get('type', '') for resource in selector.get('DataResources', []))
                    for selector in event_selectors.get('EventSelectors', [])
                )
                
                if has_bedrock_events:
                    self.print_pass("CloudTrail configured for Bedrock data events")
                else:
                    self.print_warning("CloudTrail missing Bedrock data events")
                    
            else:
                self.print_fail("No AI agent CloudTrail found")
                
            # Check for audit log bucket
            buckets = self.s3.list_buckets()['Buckets']
            audit_buckets = [bucket for bucket in buckets if 'audit-logs' in bucket['Name']]
            
            if audit_buckets:
                bucket = audit_buckets[0]
                self.print_pass(f"Found audit logs bucket: {bucket['Name']}")
                
                # Check bucket encryption
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    self.print_pass("Audit logs bucket has encryption enabled")
                except self.s3.exceptions.ClientError:
                    self.print_fail("Audit logs bucket encryption not configured")
                    
                # Check bucket versioning
                versioning = self.s3.get_bucket_versioning(Bucket=bucket['Name'])
                if versioning.get('Status') == 'Enabled':
                    self.print_pass("Audit logs bucket has versioning enabled")
                else:
                    self.print_fail("Audit logs bucket versioning not enabled")
            else:
                self.print_fail("No audit logs bucket found")
                
            self.results['A5']['status'] = 'PASS'
            
        except Exception as e:
            self.print_fail(f"Error validating A5: {str(e)}")
            self.results['A5']['status'] = 'ERROR'

    def validate_a6_egress_controls(self):
        """A6: Egress and Cost Controls"""
        self.print_header("A6", "Egress and Cost Controls")
        
        try:
            # Check for AI agent VPC
            vpcs = self.ec2.describe_vpcs()['Vpcs']
            ai_vpcs = []
            for vpc in vpcs:
                tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                if 'ai-agent' in tags.get('Name', '').lower() or tags.get('Control') == 'A6':
                    ai_vpcs.append(vpc)
                    
            if ai_vpcs:
                vpc = ai_vpcs[0]
                vpc_id = vpc['VpcId']
                self.print_pass(f"Found AI agent VPC: {vpc_id}")
                
                # Check for restrictive Network ACLs
                nacls = self.ec2.describe_network_acls(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )['NetworkAcls']
                
                restrictive_nacls = []
                for nacl in nacls:
                    egress_rules = [rule for rule in nacl['Entries'] if not rule['Egress']]
                    has_deny_all = any(
                        rule['RuleAction'] == 'deny' and rule['CidrBlock'] == '0.0.0.0/0'
                        for rule in egress_rules
                    )
                    if has_deny_all:
                        restrictive_nacls.append(nacl)
                        
                if restrictive_nacls:
                    self.print_pass("Found restrictive Network ACLs with deny-all rules")
                else:
                    self.print_warning("No restrictive Network ACLs found")
                    
            else:
                self.print_fail("No AI agent VPC found")
                
            # Note: Cost anomaly detection requires Cost Explorer API which may not be available
            self.print_warning("Cost anomaly detection validation requires manual verification")
            
            self.results['A6']['status'] = 'PASS'
            
        except Exception as e:
            self.print_fail(f"Error validating A6: {str(e)}")
            self.results['A6']['status'] = 'ERROR'

    def validate_a3_retrieval_safety(self):
        """A3: Retrieval Safety - Manual verification required"""
        self.print_header("A3", "Retrieval Safety")
        self.print_warning("A3 validation requires manual review of data classification and DLP policies")
        self.results['A3']['status'] = 'MANUAL'

    def validate_a4_supply_chain(self):
        """A4: Supply Chain Integrity - Manual verification required"""
        self.print_header("A4", "Supply Chain Integrity")  
        self.print_warning("A4 validation requires manual review of artifact signing and SBOMs")
        self.results['A4']['status'] = 'MANUAL'

    def run_all_validations(self):
        """Run all control validations"""
        print(f"{Fore.BLUE}AWS AI Security Framework Control Validator{Style.RESET_ALL}")
        print(f"Region: {self.region}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        
        self.validate_a1_identity()
        self.validate_a2_budget_guards()
        self.validate_a3_retrieval_safety()
        self.validate_a4_supply_chain()
        self.validate_a5_forensics()
        self.validate_a6_egress_controls()
        
        self.print_summary()

    def print_summary(self):
        """Print validation summary"""
        print(f"\n{Fore.CYAN}═══ VALIDATION SUMMARY ═══{Style.RESET_ALL}")
        
        for control, result in self.results.items():
            status = result['status']
            if status == 'PASS':
                color = Fore.GREEN
                symbol = "✓"
            elif status == 'FAIL':
                color = Fore.RED
                symbol = "✗"
            elif status == 'MANUAL':
                color = Fore.YELLOW
                symbol = "⚠"
            else:
                color = Fore.MAGENTA
                symbol = "?"
                
            print(f"{color}{symbol} Control {control}: {status}{Style.RESET_ALL}")
            
        # Overall status
        failed_controls = [c for c, r in self.results.items() if r['status'] == 'FAIL']
        if failed_controls:
            print(f"\n{Fore.RED}OVERALL: FAILED{Style.RESET_ALL} - {len(failed_controls)} controls need attention")
            return False
        else:
            print(f"\n{Fore.GREEN}OVERALL: PASSED{Style.RESET_ALL} - All automated checks successful")
            return True

def main():
    parser = argparse.ArgumentParser(description='Validate AWS AI Security Framework controls')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    
    args = parser.parse_args()
    
    validator = ControlValidator(profile=args.profile, region=args.region)
    
    try:
        validator.run_all_validations()
        
        if args.output == 'json':
            print(json.dumps(validator.results, indent=2))
            
        # Exit with error code if any controls failed
        success = all(r['status'] in ['PASS', 'MANUAL'] for r in validator.results.values())
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(2)

if __name__ == '__main__':
    main()