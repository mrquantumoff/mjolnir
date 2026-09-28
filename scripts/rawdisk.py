import os, sys, time, threading
path = sys.argv[1]
size = 2 << 30
block = 1 << 20
buf = os.urandom(block)

def one_writer():
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0))
    t = time.perf_counter()
    for _ in range(size // block):
        os.write(fd, buf)
    os.fsync(fd)
    os.close(fd)
    return time.perf_counter() - t

def eight_writers():
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0))
    os.ftruncate(fd, size)
    os.close(fd)
    n = 8
    def work(k):
        f = open(path, "r+b", buffering=0)
        for i in range(k, size // block, n):
            f.seek(i * block)
            f.write(buf)
        f.close()
    t = time.perf_counter()
    ts = [threading.Thread(target=work, args=(k,)) for k in range(n)]
    for x in ts: x.start()
    for x in ts: x.join()
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    os.fsync(fd)
    os.close(fd)
    return time.perf_counter() - t

for name, fn in [("1 writer, sequential", one_writer), ("8 writers, interleaved 1 MiB", eight_writers)]:
    rates = sorted((size / (1 << 20)) / fn() for _ in range(3))
    print(f"{name}: median {rates[1]:.0f} MiB/s (min {rates[0]:.0f}, max {rates[2]:.0f})")
os.remove(path)
