Firstly, install the requirements.

```bash
pip3 install -r requirements.txt
```

Then execute.

```bash
python3 main.py
```

If you are ARM chip, please execute this command.

```bash
OPENBLAS_CORETYPE=ARMV8 python3 main.py
```

## References

[pypuf](https://pypuf.readthedocs.io/en/latest/)  
[Illegal instruction (core dumped) on import for numpy 1.19.5 on ARM64](https://github.com/numpy/numpy/issues/18131#top)
