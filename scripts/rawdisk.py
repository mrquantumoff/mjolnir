"""Raw write speed of the drive holding FILE: one sequential writer, then
eight threads writing interleaved 1 MiB blocks. Each run's file is checked
for length and contents before its rate counts.

usage: python scripts/rawdisk.py FILE
"""
import os, sys, time, threading

size = 2 << 30
block = 1 << 20
buf = os.urandom(block)
BINARY = getattr(os, "O_BINARY", 0)


def write_all(write, data):
    """Calls write until all of data is written; a short write continues."""
    view = memoryview(data)
    while view:
        n = write(view)
        if not n:
            raise OSError(f"write returned {n!r} with {len(view)} bytes left")
        view = view[n:]


def one_writer(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | BINARY)
    try:
        t = time.perf_counter()
        for _ in range(size // block):
            write_all(lambda v: os.write(fd, v), buf)
        os.fsync(fd)
        return time.perf_counter() - t
    finally:
        os.close(fd)


def eight_writers(path):
    # Not pre-sized: Python's ftruncate zero-fills on Windows, and 2 GiB of
    # zeros would still be flushing while the timed writes run.
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | BINARY))
    n = 8
    errors = []

    def work(k):
        try:
            with open(path, "r+b", buffering=0) as f:
                for i in range(k, size // block, n):
                    f.seek(i * block)
                    write_all(f.write, buf)
        except BaseException as e:
            errors.append(e)

    t = time.perf_counter()
    ts = [threading.Thread(target=work, args=(k,)) for k in range(n)]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    if errors:
        raise errors[0]
    fd = os.open(path, os.O_WRONLY | BINARY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return time.perf_counter() - t


def check(path):
    """Fails unless path holds exactly size bytes, every block equal to buf."""
    got = os.path.getsize(path)
    if got != size:
        raise RuntimeError(f"{path} is {got} bytes, expected {size}")
    with open(path, "rb") as f:
        for i in range(size // block):
            if f.read(block) != buf:
                raise RuntimeError(f"{path}: block {i} does not match what was written")


def measure(fn, path):
    elapsed = fn(path)
    check(path)
    return (size / (1 << 20)) / elapsed


def main(path):
    try:
        for name, fn in [("1 writer, sequential", one_writer), ("8 writers, interleaved 1 MiB", eight_writers)]:
            rates = sorted(measure(fn, path) for _ in range(3))
            print(f"{name}: median {rates[1]:.0f} MiB/s (min {rates[0]:.0f}, max {rates[2]:.0f})")
    finally:
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    main(sys.argv[1])
