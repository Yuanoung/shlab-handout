# CS:APP Shell Lab

    http://csapp.cs.cmu.edu/3e/labs.html

## Files

- `Makefile`: Compiles your shell program and runs the tests
- `README.md`: This file
- `tsh.c`: The shell program that you will write and hand in
- `tshref`: The reference shell binary.

## The remaining files are used to test your shell

- `sdriver.pl`: The trace-driven shell driver
- `trace*.txt`: The 15 trace files that control the shell driver
- `tshref.out`: Example output of the reference shell on all 15 traces

## Little C programs that are called by the trace files

- `myspin.c`: Takes argument and spins for seconds
- `mysplit.c`: Forks a child that spins for seconds
- `mystop.c`: Spins for seconds and sends SIGTSTP to itself
- `myint.c`: Spins for seconds and sends SIGINT to itself

