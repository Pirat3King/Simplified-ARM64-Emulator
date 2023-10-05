Create your own test:
1. Write a C program and save as main.c
2. Compile without linking using the command: gcc -O0 -c -o main.o main.c
3. Disassemble the instructions with: objdump -d main.o > mytest.txt
4. Open the text file and remove the first few lines so that instruction #0 is the first line
