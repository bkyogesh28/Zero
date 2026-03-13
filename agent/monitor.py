import time
import socket
from datetime import datetime

import psutil

from metadata import build_metadata
from sender import send_event


seen_pids = set()


def monitor_processes():
    hostname = socket.gethostname()

    while True:
        for proc in psutil.process_iter():
            pid = proc.pid

            if pid in seen_pids:
                continue

            seen_pids.add(pid)

            metadata = build_metadata(proc)
            if not metadata:
                continue

            event = {
                "hostname": hostname,
                **metadata,
                "timestamp": datetime.utcnow().isoformat()
            }

            print(event)
            send_event(event)

        time.sleep(1)


if __name__ == "__main__":
    monitor_processes()