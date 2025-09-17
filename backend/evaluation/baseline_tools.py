"""
Baseline tool runners for comparison against conventional tools.

Supports XSStrike, SQLmap, and FFUF for comparative evaluation.
"""

import subprocess
import json
import time
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

from .metrics import VulnerabilityInstance, GroundTruth

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result from running a baseline tool."""
    tool_name: str
    vulnerabilities: List[VulnerabilityInstance]
    execution_time: float
    command_used: str
    raw_output: str
    errors: List[str]


class BaselineToolRunner:
    """Base class for running baseline security tools."""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or self._find_tool_path()
        self.temp_dir = None
    
    def _find_tool_path(self) -> str:
        """Find the tool executable path."""
        raise NotImplementedError
    
    def _create_temp_dir(self) -> Path:
        """Create temporary directory for tool output."""
        if self.temp_dir is None:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="elise_baseline_"))
        return self.temp_dir
    
    def cleanup(self):
        """Clean up temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
    
    def run(self, target_url: str, **kwargs) -> ToolResult:
        """Run the tool against target URL."""
        raise NotImplementedError


class XSStrikeRunner(BaselineToolRunner):
    """Runner for XSStrike XSS detection tool."""
    
    def _find_tool_path(self) -> str:
        """Find XSStrike executable."""
        # Try common locations
        possible_paths = [
            "xsser",
            "xsser.py", 
            "/usr/bin/xsser",
            "/usr/local/bin/xsser",
            "python3 -m xsser",
            "python -m xsser"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--help"], 
                                      capture_output=True, 
                                      timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        raise FileNotFoundError("XSStrike not found. Install with: pip install xsser")
    
    def run(self, target_url: str, **kwargs) -> ToolResult:
        """Run XSStrike against target URL."""
        start_time = time.time()
        vulnerabilities = []
        errors = []
        
        try:
            # XSStrike command
            cmd = [
                self.tool_path,
                "--url", target_url,
                "--threads", "10",
                "--timeout", "30",
                "--json"
            ]
            
            # Add additional parameters if provided
            if kwargs.get('crawl', False):
                cmd.extend(["--crawl", "2"])
            
            if kwargs.get('forms', False):
                cmd.extend(["--forms"])
            
            logger.info(f"Running XSStrike: {' '.join(cmd)}")
            
            # Run XSStrike
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            execution_time = time.time() - start_time
            
            # Parse XSStrike output
            if result.returncode == 0 and result.stdout:
                try:
                    # XSStrike might output JSON or plain text
                    if result.stdout.strip().startswith('{'):
                        data = json.loads(result.stdout)
                        vulnerabilities = self._parse_xsser_json(data, target_url)
                    else:
                        vulnerabilities = self._parse_xsser_text(result.stdout, target_url)
                except json.JSONDecodeError:
                    vulnerabilities = self._parse_xsser_text(result.stdout, target_url)
            
            if result.stderr:
                errors.append(f"XSStrike stderr: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            errors.append("XSStrike timed out")
        except Exception as e:
            execution_time = time.time() - start_time
            errors.append(f"XSStrike error: {str(e)}")
        
        return ToolResult(
            tool_name="XSStrike",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            command_used=" ".join(cmd),
            raw_output=result.stdout if 'result' in locals() else "",
            errors=errors
        )
    
    def _parse_xsser_json(self, data: Dict, target_url: str) -> List[VulnerabilityInstance]:
        """Parse XSStrike JSON output."""
        vulnerabilities = []
        
        # XSStrike JSON format varies, adapt as needed
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('vulnerable'):
                    vuln = VulnerabilityInstance(
                        endpoint=item.get('url', target_url),
                        parameter=item.get('parameter', 'unknown'),
                        vulnerability_type='xss',
                        payload=item.get('payload', ''),
                        confirmed=True,
                        confidence=item.get('confidence', 0.8),
                        detection_time=item.get('time', 0.0),
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_xsser_text(self, output: str, target_url: str) -> List[VulnerabilityInstance]:
        """Parse XSStrike text output."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if 'vulnerable' in line.lower() or 'xss' in line.lower():
                # Extract payload and parameter from line
                # This is a simplified parser - adapt based on actual XSStrike output
                parts = line.split()
                if len(parts) >= 2:
                    payload = parts[-1] if parts else ''
                    vuln = VulnerabilityInstance(
                        endpoint=target_url,
                        parameter='unknown',
                        vulnerability_type='xss',
                        payload=payload,
                        confirmed=True,
                        confidence=0.7,
                        detection_time=0.0,
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities


class SQLmapRunner(BaselineToolRunner):
    """Runner for SQLmap SQL injection detection tool."""
    
    def _find_tool_path(self) -> str:
        """Find SQLmap executable."""
        possible_paths = [
            "sqlmap",
            "sqlmap.py",
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "python3 -m sqlmap",
            "python -m sqlmap"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--help"], 
                                      capture_output=True, 
                                      timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        raise FileNotFoundError("SQLmap not found. Install from: https://github.com/sqlmapproject/sqlmap")
    
    def run(self, target_url: str, **kwargs) -> ToolResult:
        """Run SQLmap against target URL."""
        start_time = time.time()
        vulnerabilities = []
        errors = []
        temp_dir = self._create_temp_dir()
        
        try:
            # SQLmap command
            output_file = temp_dir / "sqlmap_results.json"
            cmd = [
                self.tool_path,
                "--url", target_url,
                "--batch",  # Non-interactive mode
                "--output-dir", str(temp_dir),
                "--output-file", str(output_file),
                "--risk", "3",
                "--level", "3",
                "--threads", "10",
                "--timeout", "30"
            ]
            
            # Add additional parameters
            if kwargs.get('forms', False):
                cmd.append("--forms")
            
            if kwargs.get('crawl', False):
                cmd.extend(["--crawl", "2"])
            
            logger.info(f"Running SQLmap: {' '.join(cmd)}")
            
            # Run SQLmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            execution_time = time.time() - start_time
            
            # Parse SQLmap output
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    vulnerabilities = self._parse_sqlmap_json(data, target_url)
                except (json.JSONDecodeError, FileNotFoundError):
                    # Fallback to parsing stdout
                    vulnerabilities = self._parse_sqlmap_text(result.stdout, target_url)
            else:
                vulnerabilities = self._parse_sqlmap_text(result.stdout, target_url)
            
            if result.stderr:
                errors.append(f"SQLmap stderr: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            errors.append("SQLmap timed out")
        except Exception as e:
            execution_time = time.time() - start_time
            errors.append(f"SQLmap error: {str(e)}")
        
        return ToolResult(
            tool_name="SQLmap",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            command_used=" ".join(cmd),
            raw_output=result.stdout if 'result' in locals() else "",
            errors=errors
        )
    
    def _parse_sqlmap_json(self, data: Dict, target_url: str) -> List[VulnerabilityInstance]:
        """Parse SQLmap JSON output."""
        vulnerabilities = []
        
        # SQLmap JSON format parsing
        if 'targets' in data:
            for target in data['targets']:
                if target.get('vulnerable'):
                    vuln = VulnerabilityInstance(
                        endpoint=target.get('url', target_url),
                        parameter=target.get('parameter', 'unknown'),
                        vulnerability_type='sqli',
                        payload=target.get('payload', ''),
                        confirmed=True,
                        confidence=target.get('confidence', 0.9),
                        detection_time=target.get('time', 0.0),
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_sqlmap_text(self, output: str, target_url: str) -> List[VulnerabilityInstance]:
        """Parse SQLmap text output."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if 'vulnerable' in line.lower() or 'injection' in line.lower():
                # Extract parameter and payload from line
                parts = line.split()
                if len(parts) >= 2:
                    vuln = VulnerabilityInstance(
                        endpoint=target_url,
                        parameter='unknown',
                        vulnerability_type='sqli',
                        payload='',
                        confirmed=True,
                        confidence=0.8,
                        detection_time=0.0,
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities


class FFUFRunner(BaselineToolRunner):
    """Runner for FFUF fuzzing tool."""
    
    def _find_tool_path(self) -> str:
        """Find FFUF executable."""
        possible_paths = [
            "ffuf",
            "/usr/bin/ffuf",
            "/usr/local/bin/ffuf"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "-h"], 
                                      capture_output=True, 
                                      timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        raise FileNotFoundError("FFUF not found. Install from: https://github.com/ffuf/ffuf")
    
    def run(self, target_url: str, **kwargs) -> ToolResult:
        """Run FFUF against target URL."""
        start_time = time.time()
        vulnerabilities = []
        errors = []
        temp_dir = self._create_temp_dir()
        
        try:
            # FFUF command for parameter fuzzing
            output_file = temp_dir / "ffuf_results.json"
            cmd = [
                self.tool_path,
                "-u", f"{target_url}?FUZZ=test",
                "-w", "/usr/share/wordlists/common.txt",  # Common parameter names
                "-o", str(output_file),
                "-of", "json",
                "-t", "10",
                "-timeout", "30"
            ]
            
            logger.info(f"Running FFUF: {' '.join(cmd)}")
            
            # Run FFUF
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            execution_time = time.time() - start_time
            
            # Parse FFUF output
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    vulnerabilities = self._parse_ffuf_json(data, target_url)
                except (json.JSONDecodeError, FileNotFoundError):
                    vulnerabilities = self._parse_ffuf_text(result.stdout, target_url)
            else:
                vulnerabilities = self._parse_ffuf_text(result.stdout, target_url)
            
            if result.stderr:
                errors.append(f"FFUF stderr: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            errors.append("FFUF timed out")
        except Exception as e:
            execution_time = time.time() - start_time
            errors.append(f"FFUF error: {str(e)}")
        
        return ToolResult(
            tool_name="FFUF",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            command_used=" ".join(cmd),
            raw_output=result.stdout if 'result' in locals() else "",
            errors=errors
        )
    
    def _parse_ffuf_json(self, data: Dict, target_url: str) -> List[VulnerabilityInstance]:
        """Parse FFUF JSON output."""
        vulnerabilities = []
        
        # FFUF finds parameters, not necessarily vulnerabilities
        # This is more for endpoint discovery
        if 'results' in data:
            for result in data['results']:
                if result.get('status') == 200:  # Successful response
                    vuln = VulnerabilityInstance(
                        endpoint=result.get('url', target_url),
                        parameter=result.get('input', {}).get('FUZZ', 'unknown'),
                        vulnerability_type='endpoint_discovery',
                        payload='',
                        confirmed=False,  # FFUF doesn't confirm vulnerabilities
                        confidence=0.5,
                        detection_time=0.0,
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_ffuf_text(self, output: str, target_url: str) -> List[VulnerabilityInstance]:
        """Parse FFUF text output."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('['):
                # Extract parameter from line
                parts = line.split()
                if len(parts) >= 2:
                    vuln = VulnerabilityInstance(
                        endpoint=target_url,
                        parameter=parts[0] if parts else 'unknown',
                        vulnerability_type='endpoint_discovery',
                        payload='',
                        confirmed=False,
                        confidence=0.5,
                        detection_time=0.0,
                        attempt_count=1
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities


class BaselineToolManager:
    """Manager for running multiple baseline tools."""
    
    def __init__(self, initialize_tools: bool = True):
        self.tools = {}
        if initialize_tools:
            try:
                self.tools['xsser'] = XSStrikeRunner()
            except FileNotFoundError:
                pass
            try:
                self.tools['sqlmap'] = SQLmapRunner()
            except FileNotFoundError:
                pass
            try:
                self.tools['ffuf'] = FFUFRunner()
            except FileNotFoundError:
                pass
    
    def run_all_tools(self, target_url: str, **kwargs) -> Dict[str, ToolResult]:
        """Run all available baseline tools."""
        results = {}
        
        for tool_name, tool_runner in self.tools.items():
            try:
                logger.info(f"Running {tool_name} against {target_url}")
                result = tool_runner.run(target_url, **kwargs)
                results[tool_name] = result
            except Exception as e:
                logger.error(f"Failed to run {tool_name}: {str(e)}")
                results[tool_name] = ToolResult(
                    tool_name=tool_name,
                    vulnerabilities=[],
                    execution_time=0.0,
                    command_used="",
                    raw_output="",
                    errors=[str(e)]
                )
        
        return results
    
    def cleanup(self):
        """Clean up all tool runners."""
        for tool_runner in self.tools.values():
            tool_runner.cleanup()
