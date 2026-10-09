"""whatweb scanning plugin."""
import random
import asyncio
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Whatweb:
    """Scan http services"""
    name: str = "Whatweb"
    description: str = "http scanning with whatweb"
    tag: List[str] = field(default_factory=lambda: ["scans", "Whatweb"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^https'))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module, semaphore, lock):
        sleep_time = random.randint(7, 15)
        await asyncio.sleep(sleep_time)    
        """Run whatweb scan."""
        cmd = f"/usr/bin/whatweb --no-errors -a 3 -v {service}://{target}:{port} 2>&1 | tee {output}/scans/{protocol}_{port}_{service}_whatweb.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module, semaphore=semaphore, lock=lock)
