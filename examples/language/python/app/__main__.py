import sys

from fib import fib as fib2

if __name__ == "__main__":
    count = sys.argv[1]
    print(f"outputing fib to {count}")
    fib2(int(count))
