#!/usr/bin/env python3
"""
Elise Unified Workflow Script

Orchestrates the complete build/train/reassess/export/scorecard pipeline for Elise.

Usage:
    python scripts/elise_workflow.py --target https://localhost:8443/benchmark/ --workflow full
    python scripts/elise_workflow.py --job-id existing_job --workflow reassess
    python scripts/elise_workflow.py --target https://example.com --workflow build-train
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from backend.modules.playwright_crawler import crawl_site
from backend.pipeline.workflow import assess_endpoints

class EliseWorkflow:
    """Unified workflow orchestrator for Elise build/train/reassess/export/scorecard pipeline."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.job_id = config.get('job_id') or f"workflow-{int(time.time()*1000)}"
        self.work_dir = Path('backend/data/jobs') / self.job_id
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Workflow state
        self.state = {
            'job_id': self.job_id,
            'started_at': datetime.now().isoformat(),
            'steps_completed': [],
            'results': {}
        }
        
    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def run_command(self, cmd: List[str], description: str) -> Dict[str, Any]:
        """Run a command and return results."""
        self.log(f"Running: {description}")
        self.log(f"Command: {' '.join(cmd)}")
        
        # Use venv Python if available
        venv_python = Path(__file__).parent.parent / 'venv' / 'bin' / 'python'
        if venv_python.exists() and cmd[0] == sys.executable:
            cmd[0] = str(venv_python)
            self.log(f"Using venv Python: {cmd[0]}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True,
                cwd=Path(__file__).parent.parent
            )
            
            self.log(f"✅ {description} completed successfully")
            return {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.CalledProcessError as e:
            self.log(f"❌ {description} failed: {e}", "ERROR")
            return {
                'success': False,
                'stdout': e.stdout,
                'stderr': e.stderr,
                'returncode': e.returncode,
                'error': str(e)
            }
    
    def step_build_datasets(self) -> bool:
        """Step 1: Build training datasets from evidence."""
        self.log("=== STEP 1: Building Training Datasets ===")
        
        # Check if we have any evidence files
        evidence_files = list(Path('backend/data/jobs').glob('**/*_*.json'))
        if not evidence_files:
            self.log("No evidence files found, skipping dataset building", "WARNING")
            self.state['steps_completed'].append('build_datasets')
            self.state['results']['build_datasets'] = {'success': True, 'skipped': True, 'reason': 'no_evidence_files'}
            return True
        
        # Build ranker dataset
        cmd = [
            sys.executable, 'scripts/build_ranker_dataset.py',
            '--glob', 'backend/data/jobs/**/*_*.json',
            '--out', 'backend/modules/ml/data/ranker',
            '--min-conf', '0.0'
        ]
        
        result = self.run_command(cmd, "Building ranker dataset")
        if not result['success']:
            self.log("Dataset building failed, but continuing workflow", "WARNING")
            result['skipped'] = True
            
        # Build XSS payload ranking dataset
        cmd = [
            sys.executable, 'scripts/build_xss_payload_ranking_dataset.py',
            '--jobs-dir', 'backend/data/jobs',
            '--out', 'backend/modules/ml/data/xss_ranking.jsonl'
        ]
        
        result2 = self.run_command(cmd, "Building XSS payload ranking dataset")
        if not result2['success']:
            self.log("XSS dataset building failed, but continuing workflow", "WARNING")
            result2['skipped'] = True
            
        self.state['steps_completed'].append('build_datasets')
        self.state['results']['build_datasets'] = {'ranker': result, 'xss': result2}
        return True
    
    def step_train_models(self) -> bool:
        """Step 2: Train ML models."""
        self.log("=== STEP 2: Training ML Models ===")
        
        # Check if we have training data
        ranker_dataset = Path('backend/modules/ml/data/ranker/ranker_dataset.jsonl')
        if not ranker_dataset.exists():
            self.log("No ranker dataset found, skipping model training", "WARNING")
            self.state['steps_completed'].append('train_models')
            self.state['results']['train_models'] = {'success': True, 'skipped': True, 'reason': 'no_training_data'}
            return True
        
        # Train XSS ranker
        cmd = [
            sys.executable, 'scripts/train_xss_ranker.py',
            '--dataset', 'backend/modules/ml/data/ranker/ranker_dataset.jsonl',
            '--outdir', 'backend/modules/ml/models'
        ]
        
        result = self.run_command(cmd, "Training XSS ranker")
        if not result['success']:
            self.log("XSS ranker training failed, but continuing workflow", "WARNING")
            result['skipped'] = True
            
        # Train general ranker models
        cmd = [
            sys.executable, 'backend/modules/ml/train_ranker.py',
            '--data-glob', 'backend/data/jobs/**/*_*.json',
            '--out-dir', 'backend/modules/ml/models',
            '--families', 'sqli', 'xss', 'redirect'
        ]
        
        result2 = self.run_command(cmd, "Training general ranker models")
        if not result2['success']:
            self.log("General ranker training failed, but continuing workflow", "WARNING")
            result2['skipped'] = True
            
        self.state['steps_completed'].append('train_models')
        self.state['results']['train_models'] = {'xss_ranker': result, 'general_ranker': result2}
        return True
    
    def step_crawl_target(self) -> bool:
        """Step 3: Crawl target to discover endpoints."""
        if not self.config.get('target_url'):
            self.log("No target URL provided, skipping crawl", "WARNING")
            return True
            
        self.log("=== STEP 3: Crawling Target ===")
        
        target_url = self.config['target_url']
        crawl_opts = self.config.get('crawl_opts', {})
        
        self.log(f"Crawling: {target_url}")
        
        try:
            # Set environment for insecure TLS if needed
            if self.config.get('insecure_tls', False):
                os.environ['ELISE_TLS_INSECURE'] = '1'
                
            crawl_result = crawl_site(
                target_url=target_url,
                max_depth=crawl_opts.get('max_depth', 5),
                max_endpoints=crawl_opts.get('max_endpoints', 2000),
                max_seconds=crawl_opts.get('max_seconds', 900),
                submit_get_forms=crawl_opts.get('submit_get_forms', True),
                submit_post_forms=crawl_opts.get('submit_post_forms', True),
                click_buttons=crawl_opts.get('click_buttons', True)
            )
            
            endpoints = crawl_result.get('endpoints', [])
            meta = crawl_result.get('meta', {})
            
            self.log(f"Discovered {len(endpoints)} endpoints")
            
            # Save endpoints
            endpoints_file = self.work_dir / 'endpoints.json'
            with endpoints_file.open('w') as f:
                json.dump({
                    'job_id': self.job_id,
                    'target_url': target_url,
                    'crawl_opts': crawl_opts,
                    'endpoints': endpoints,
                    'meta': meta
                }, f, indent=2)
                
            self.state['endpoints'] = endpoints
            self.state['steps_completed'].append('crawl_target')
            self.state['results']['crawl_target'] = {
                'success': True,
                'endpoints_count': len(endpoints),
                'endpoints_file': str(endpoints_file)
            }
            
            return True
            
        except Exception as e:
            self.log(f"Crawl failed: {e}", "ERROR")
            return False
    
    def step_reassess_endpoints(self) -> bool:
        """Step 4: Reassess endpoints for vulnerabilities."""
        self.log("=== STEP 4: Reassessing Endpoints ===")
        
        # Load endpoints if not already loaded
        if 'endpoints' not in self.state:
            endpoints_file = self.work_dir / 'endpoints.json'
            if not endpoints_file.exists():
                self.log("No endpoints found, skipping reassessment", "WARNING")
                return True
                
            with endpoints_file.open('r') as f:
                data = json.load(f)
                self.state['endpoints'] = data['endpoints']
        
        endpoints = self.state['endpoints']
        if not endpoints:
            self.log("No endpoints to assess", "WARNING")
            return True
            
        # Set environment for insecure TLS if needed
        if self.config.get('insecure_tls', False):
            os.environ['ELISE_TLS_INSECURE'] = '1'
            
        try:
            assessment_result = assess_endpoints(
                endpoints=endpoints,
                job_id=self.job_id,
                top_k=self.config.get('top_k', 7),
                strategy=self.config.get('strategy', 'auto'),
                ctx_mode=self.config.get('ctx_mode', 'always'),
                sqli_ml_mode=self.config.get('sqli_ml_mode', 'never')
            )
            
            summary = assessment_result.get('summary', {})
            findings = assessment_result.get('findings', [])
            
            self.log(f"Assessment completed: {summary.get('positive', 0)} positives, {summary.get('suspected', 0)} suspected")
            
            # Save assessment results
            results_file = self.work_dir / 'assessment_results.json'
            with results_file.open('w') as f:
                json.dump(assessment_result, f, indent=2)
                
            self.state['assessment_result'] = assessment_result
            self.state['steps_completed'].append('reassess_endpoints')
            self.state['results']['reassess_endpoints'] = {
                'success': True,
                'summary': summary,
                'findings_count': len(findings),
                'results_file': str(results_file)
            }
            
            return True
            
        except Exception as e:
            self.log(f"Assessment failed: {e}", "ERROR")
            return False
    
    def step_export_results(self) -> bool:
        """Step 5: Export results to ZAP JSON format."""
        self.log("=== STEP 5: Exporting Results ===")
        
        # Export to ZAP JSON
        export_file = self.work_dir / 'zap_export.json'
        cmd = [
            sys.executable, 'scripts/export_elise_to_zapjson.py',
            '--job-id', self.job_id,
            '--out', str(export_file),
            '--base', self.config.get('export_base_url', 'https://localhost:8443/benchmark')
        ]
        
        result = self.run_command(cmd, "Exporting to ZAP JSON")
        if not result['success']:
            return False
            
        self.state['steps_completed'].append('export_results')
        self.state['results']['export_results'] = result
        return True
    
    def step_scorecard(self) -> bool:
        """Step 6: Generate scorecard and metrics."""
        self.log("=== STEP 6: Generating Scorecard ===")
        
        # Download expected results if not present
        expected_file = Path('/tmp/expectedresults-1.2.csv')
        if not expected_file.exists():
            self.log("Downloading OWASP Benchmark expected results...")
            download_cmd = [
                'curl', '-fsSL',
                'https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv',
                '-o', str(expected_file)
            ]
            download_result = self.run_command(download_cmd, "Downloading expected results")
            if not download_result['success']:
                self.log("Failed to download expected results, skipping scorecard", "WARNING")
                return True
        
        # Generate scorecard
        scorecard_file = self.work_dir / 'scorecard.txt'
        cmd = [
            sys.executable, 'scripts/score_benchmark_xss.py',
            '--job-id', self.job_id,
            '--expected', str(expected_file)
        ]
        
        result = self.run_command(cmd, "Generating scorecard")
        if not result['success']:
            return False
            
        # Save scorecard output
        with scorecard_file.open('w') as f:
            f.write(result['stdout'])
            
        self.log(f"Scorecard saved to: {scorecard_file}")
        print("\n" + "="*60)
        print("SCORECARD RESULTS:")
        print("="*60)
        print(result['stdout'])
        print("="*60)
        
        self.state['steps_completed'].append('scorecard')
        self.state['results']['scorecard'] = result
        return True
    
    def run_workflow(self, workflow_type: str) -> bool:
        """Run the specified workflow."""
        self.log(f"Starting Elise workflow: {workflow_type}")
        self.log(f"Job ID: {self.job_id}")
        
        success = True
        
        if workflow_type in ['full', 'build-train']:
            success &= self.step_build_datasets()
            success &= self.step_train_models()
            
        if workflow_type in ['full', 'reassess']:
            success &= self.step_crawl_target()
            success &= self.step_reassess_endpoints()
            
        if workflow_type in ['full', 'export-scorecard']:
            success &= self.step_export_results()
            success &= self.step_scorecard()
            
        # Save workflow state
        self.state['completed_at'] = datetime.now().isoformat()
        self.state['success'] = success
        
        state_file = self.work_dir / 'workflow_state.json'
        with state_file.open('w') as f:
            json.dump(self.state, f, indent=2)
            
        if success:
            self.log("🎉 Workflow completed successfully!")
        else:
            self.log("❌ Workflow completed with errors", "ERROR")
            
        return success

def main():
    parser = argparse.ArgumentParser(description="Elise Unified Workflow Script")
    
    # Workflow configuration
    parser.add_argument('--workflow', required=True, 
                       choices=['full', 'build-train', 'reassess', 'export-scorecard'],
                       help='Workflow type to run')
    
    # Target configuration
    parser.add_argument('--target', help='Target URL to crawl and assess')
    parser.add_argument('--job-id', help='Existing job ID (for reassess/export workflows)')
    
    # Crawl options
    parser.add_argument('--max-depth', type=int, default=5, help='Max crawl depth')
    parser.add_argument('--max-endpoints', type=int, default=2000, help='Max endpoints to discover')
    parser.add_argument('--max-seconds', type=int, default=900, help='Max crawl time in seconds')
    parser.add_argument('--insecure-tls', action='store_true', help='Allow insecure TLS connections')
    
    # Assessment options
    parser.add_argument('--strategy', default='auto', help='Assessment strategy')
    parser.add_argument('--ctx-mode', default='always', help='XSS context mode')
    parser.add_argument('--sqli-ml-mode', default='never', help='SQLi ML mode')
    parser.add_argument('--top-k', type=int, default=7, help='Top K payloads to test')
    
    # Export options
    parser.add_argument('--export-base-url', default='https://localhost:8443/benchmark',
                       help='Base URL for ZAP export')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.workflow in ['reassess', 'export-scorecard'] and not args.job_id:
        parser.error("--job-id is required for reassess and export-scorecard workflows")
    
    if args.workflow in ['full', 'build-train'] and not args.target:
        parser.error("--target is required for full and build-train workflows")
    
    # Create configuration
    config = {
        'job_id': args.job_id,
        'target_url': args.target,
        'crawl_opts': {
            'max_depth': args.max_depth,
            'max_endpoints': args.max_endpoints,
            'max_seconds': args.max_seconds,
            'submit_get_forms': True,
            'submit_post_forms': True,
            'click_buttons': True
        },
        'insecure_tls': args.insecure_tls,
        'strategy': args.strategy,
        'ctx_mode': args.ctx_mode,
        'sqli_ml_mode': args.sqli_ml_mode,
        'top_k': args.top_k,
        'export_base_url': args.export_base_url
    }
    
    # Run workflow
    workflow = EliseWorkflow(config)
    success = workflow.run_workflow(args.workflow)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
