import sys
import logging

from monitor import monitor_processes


def main(argv=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.info("agent.main: starting")
    monitor_processes()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))