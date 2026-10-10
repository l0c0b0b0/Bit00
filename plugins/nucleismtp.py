"""nmap-smtp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiSmtp:
    """Scan smtp services"""
    name: str = "NucleiSmtp"
    description: str = "smtp scanning with nuclei-smtp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiSmtp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smtp',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module, semaphore, lock):
            
        """Run nmap-smtp scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {target}:{port} -tags smtp,cve,misconfig,exposure -rate-limit 50 -concurrency 5 -retries 3 -max-host-error 3 -no-httpx -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module, semaphore=semaphore, lock=lock)
