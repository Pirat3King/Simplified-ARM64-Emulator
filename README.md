## About
Simplified ARM64 emulator

## Installation
```
pip install -r requirements.txt
```

## Usage
```
python3 ./emulator.py <file>
```

Input file must be in the ```objdump``` format, starting on address ```0```

### Example Input

```
   0:	d10043ff 	sub	sp, sp, #0x10
   4:	d2800f60 	mov	x0, #0x7b                  	// #123
   8:	f90007e0 	str	x0, [sp, #8]
   c:	f94007e0 	ldr	x0, [sp, #8]
  10:	f90003e0 	str	x0, [sp]
  14:	52800000 	mov	x0, #0x0                   	// #0
  18:	910043ff 	add	sp, sp, #0x10
  1c:	d65f03c0 	ret
```
