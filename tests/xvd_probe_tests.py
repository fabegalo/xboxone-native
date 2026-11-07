# SPDX-License-Identifier: BSD-3-Clause
"""Safety gates only. Never mounts an image or loads a Microsoft provider."""
from pathlib import Path
import subprocess
import sys
import tempfile

probe = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='xboxone_probe_test_') as temporary:
    root = Path(temporary)
    provider, image = root / 'missing.dll', root / 'missing.xvd'
    for mode in ('--bad-mode', '--mount-readonly', '--unmount-owned', '--diagnose'):
        log = root / (mode + '.log')
        result = subprocess.run([str(probe), mode, str(provider), str(image), str(log)], timeout=5)
        text = log.read_text()
        assert 'probe_completed=1' in text
        assert 'mount_readonly=' not in text and 'open_adapter=' not in text
        if mode == '--diagnose':
            assert result.returncode == 1 and 'provider_load_win32=' in text
        elif mode != '--bad-mode':
            assert result.returncode == 2 and 'gaming_services_package_context_required' in text
        else:
            assert result.returncode == 2
        assert not provider.exists() and not image.exists()
print('4 safety cases passed; no mount/deployment performed')
