; Welcome to CSAW! And, presumably, welcome to reverse engineering.
; This challenge is for N3WbS ONLY, so if you know what you're doing, then put one of your freshmen on this challenge..if you don't have any freshmen, then you need to recruit harder - for now just go steal one.  Come back when you're ready with some fresh blood, or go work on some harder challenges!

; Rule # ONE :
;  Since this problem is designed to introduce newbies to reverse engineering, I've designed this source document such that you can hopefully read it straight down and come to a reasonable understanding of this nonsense...
;    Reverse engineering is the dissection and understanding of SYSTEMS, not of CODE.. As such, you won't need to read and understand every single line so long as you can understand what is general occurring and build a working intuition of what the system is doing.
;    For example, if you see a call to `print("input: ")` then a call to `password = inputPassword()`, I would sincerely hope that you could deduce that you're being asked to input the weight of an average-sized giraffe.  (that's a joke...I do those..ask on IRC if you get caught up on something you think might be a joke..though we can't really help you during the competition..we can help clear up misunderstandings as a result of me not being an english major, but not too much beyond that)

; Alright.
; So if you're still here then you're about to learn the coolest shit ever.
; This is assembly. This is a human-readable representation of what is as close as reasonable (and still READABLE) to what the actual processor on your computer runs.
; It's worth mentioning that assembly is a dense topic, there's a lot here to understand... You should probably go take a course on this and read some book and--- WAIT!! NO!! THIS IS CSAW!!! WE LEARN THIS THE FUN WAY; MISGUIDEDLY DIVING IN HEAD FIRST AND BREAKING SHIT ALONG THE WAY.
; So here we go.

; To start, I am not going to give you a hello world world program as is standard - that would be far too complicated a program to parse.  Let's instead write a basic operating system.  Much easier, right? *eye twitch*
; Here's the bill of materials you're going to want for this challenge, and most of your future hacking/building/programing/life.... .-.
;  1. Linux, of some sort - I'm running Ubuntu 18.04 myself, and that's what a lot of other CTF problems are made to target, but there are plenty of versions of Linux out there... You'll have to reinstall whatever you setup about a million times before you actually figure out how this Unix-like shit works, so don't worry about it too much and just go install any one of them.
;      You might wish to use a Virtual Machine for this.  That would be okay.
;      If you really want, you could even containerise this.  That'd be cool... But not needed.
;      If you are on Windows, the Linux Subssytem for Windows is really nice.. I like it a lot.
;
;  2. NASM - How we convert the text below into the stuff the computer can actually read.
;      Yeah, so, uhhh, the bad news is that a computer can't understand text very well.  The good news is that it's pretty easy to make the text machine-readable: each line of ode below translates to somewhere between 1 and 15 bytes that the computer can understand perfectly - but we can only recognize as a collection of random numbers.
;      (On Ubuntu, that's a simple `sudo apt install nasm`)
;
;  3. QEMU - How we're going to run the operating system we're making
;      (On Ubuntu, that's a simple `sudo apt install qemu`)
;
;  4. Probably a text editor.  To this edit text (to solve part two).  I like VisualStudioCode.. It has some 'asm' extentions.
;
;  5. A T3rMiNaL!  They're useful.  You type things in them and make stuff happen... This should almost go without saying, but that's how we're going to interact with the tool's we are using for this challenge, and many other challenges.
;      Don't be scared though, there are many nice graphical tools you'll end up using along the way.
;
;  6. To practically advance in reverse engineering, and to advance past the first stage of this "Tour Of x86", you'll need a disassembler.
;      A disassembler takes that collection of seemingly random numbers and translates it into something a human can understand.
;      The nice disassemblers also do some extra analysis on these programs, which allow for it to more accurate disassemble the program, like BinaryNinja!! <- the best one ever. :)  And no I'm not contractually obligated to say that.  I'm also not stuck in a box.  I also don't miss the large death laser in the sky.  The death laser was mean to me.

; Damn, that was boring.

; Time for the really cool stuff! x86 assembly!
;   It's worth mentioning that there are lots of different assembly languages; since there are many different kinds of computers that have different design goals and use-cases, and "the processor" is the brain of all of these devices, there has developd a healthy handful of different assembly languages to control these different processors.
;   Two of these use-cases might include a low-power environment like your phone (where you want it to work all day), and a computationally intensive device like a server or a gaming computer... The phone would use something that was designed with low power usage in mind, like the ARM processors, whereas the desktop might use something that is more powerful/faster/has more features such as Intel's and AMD's own x86!  Which is what we'll look at because most services you'll exploit 'in their natural habitat' will be running on a heavy-duty x86 computer - tangentially, since it's designed to be more robust it is a LOT more complicated and there are sometimes glitches, which we call vulnerabilities, in the implementation of the processors' instruction that might allow us to do things that were not intended in the design - possibly leaking data.

; First things first, don't read these next three lines of code

; Tell the text to machine-code machine, NASM, where in memory our code is going to be loaded.  Hexadecimal.  Legacy BS. 
org 7C00h
; Tell Mr. Machine that we're using 16-bit assembly
bits 16

; Setting up two defines for later so we don't have magic numbers laying around.
%define LOAD_ADDR 0x6000

; Got you - I bet you even read those lines.  Ugh.

; Every program needs to start somewhere, why not start at the `_start`?
_start:  ; This is a label...  It's not an instruction.  It is simply a marker for us humans.  We put it here so we can reference it later, such that ff we later specify `_start` in our code, NASM will know we're referencing the element immediately following the label.
  cli  ; This is not an instruction you normally see... So don't worry about it.  Makes it so, like, plugging in a usb doesn't scare the processor away from us.

  ; Important: Assembly gives you a set number of variables.  These variables are called registers.  They are not variables, but you can think of them like that.  They're really fast and depending on the name you reference them by, you get different sizes of them (16 bits vs 8 bits vs 64, etc.) - they're fixed-sized slots for us to store _data_.
  ; I'm going to go ahead and clear all of the registers we have 'general' access to (and that won't cause our code to die) just so you can see what they are.. There are tons more, but these are the meat-and-gravy of what we'll use to store and manipulate data.

  mov ah, 0
  mov al, 0
  mov ax, 0

  ; Okay I'll stop myself right here.  Let's break this line down into its component parts.
  ;   `mov` - the first word that you see is called the "opcode" - the "operation code" - the short word that represent and operation performed by your code on the processor of the computer.  This one is move.  It moves stuff.
  ;   `ah`  - one of those registers I mentioned (the 'a' register...there's also 'b', 'c', 'd', and more).  It's 8 bits large... It's the smallest register size we have.
  ;   `0`   - it's.... zero.  What do you want from meee?
  ;
  ;  So in a syntax you're probably more used to:
  ;  `mov ah, 0` means `ah = 0`
  ;  since we're moving data from the right to the left... Setting ah hold the value zero.
  ;  We're doing the same to `al` and `ax`, al is another 8-bit register, and ax is 16 bits... They're all related by the `A`, though.. They're different parts of the same register:
  ;
  ;  16 bits (separated for visual effect in eight-bit chunks):
  ;
  ;  -------- --------
  ;
  ;  These are slots for 0's and ones.. Could look like:
  ;
  ;  00000000 00000000
  ;
  ;  Or whatever other binary value we set it to.
  ;
  ;  The most significant digits in the number are on the left, like we're used to.  As such, and as I have, we can separate these 16-bits into two separate halves and label them `high` (h) and `low` (l)... The higher 8-bits being the more-significant digits.
  ;  We can manipulate each of these halfs independently, for convenience.  We simply need to know how to reference them.
  ;
  ;  -------- --------
  ;     AH       AL
  ;
  ;  And the whole thing is called AX.
  ;
  ;  This is important, so, to restate... If you want to change any part of the `A` register, you need to reference which part of it you want to change.  The 16 bits, or the lower 8-bits, or the higher 8-bits.  Be "specif-bits" (specific..I know, I'm hilarious).
  ;
  ; We have registers A, B, C, and D that are the same.. Later we'll also have 8 through 15, that are similar, but we'll get to them when we get to them.

  ; Let's keep clearing our registers... Just to makes sure they're all zero when we're starting out and to show you what they all look like

  mov bh, 0
  mov bl, 0
  mov bx, 0 ; Realize that this one is pointless and redundant.

  mov ch, 1
  mov cl, 1
  mov cx, 0 ; The other two values get overwritten regardless, the value of ch and cl (the two components that make up cx) after this instruction are both 0, not 1.

  ; To prove that last comment, let's introduce a quick comparison... `cmp`
  cmp ch, 1  ; Many instructions act on more than their explicitly stated operands, in this case it sets some of the bits in a register known as the `flags` registers.. Each bit of the flags register is used as a boolean value.  You don't need to memorize what each bit holds a bool for, though, since we have other opcodes that will read and parse the flags register for us.
  ; This instruction looks at the register ch and the absolute value of "one" and sets the various field in `flags` based on the attributes that it recognizes - less than, greater than, equal, etc.
  
  je .death  ; read as "jump equal", if the two values previously compared were equal at the time of the comparison, then we will jump to the _label_ (remember... `_start`?) specified as the sole operand.  This instruction also acts on a register not explicitly stated... The "instructions pointer", which effectively holds the count of which instruction in the program we are next to execute (it really holds a pointer to the instruction loaded in memory, but pedantics...)
  jmp .next_test ; Since the two values were not equal and did not satisfy the jump condition, it instead just falls through to the next instruction, this one, which skips the death block via a unconditional jump
  
  .death:
    hlt  ; "Halt and catch fire" - stop executing code.  Immediately.  Die.  Never come back.  It's all over.  The death laser in the sky got you.  Etc.
  
  .next_test:  ;One note, I'm using NASM as a assembler (which is fairly standard), and it provides a lot of nice preprocessor things, much like `#include`s in C++ and the like.
                ; One of the things that NASM provides is 'local labels', so any label with a dot (".") in font of it, is considered local to a function (the previous label without a dot in front of it), so you can have the same label across your codebase within larger labels (tentatively called functions), just for convenience.
    cmp cl, 0
    je .success  ; If cl is indeed zero, skip the death!

    hlt  ; pls no

    .success:  ; Whitespace is ignored, btw...just like me

  ; There are other ways to make a register be set to zero... I hope you know your binary operators (and, or, not, xor, compliments)
  xor dh, dh  ; <- Question 1
  and dl, 0
  mov dx, 0xffff  ; Hexadecimal
  not dx

  cmp dx, 0
  jne .death  ; This time jumping backwards to a label we passed... Saves duplicate code.

  ; Alright, recruits! New registers!
  ; These are called segment registers and are all 16-bits only.
  ; ...Yeah...
  ; Fuckin' useless.

  mov ds, ax ; Oh yeah so this time since
  mov es, bx ; the other registers are
  mov fs, cx ; already zero, I'm just going
  mov gs, dx ; to use them to help me clear     <- Question 2
  mov ss, ax ; these registers out.

  ; Many of these registers actually have names, but they're mostly irrelevant and just legacy.
  mov sp, cx ; Stack Pointer
  mov bp, dx ; Base Pointer
  mov si, sp ; Source Index       <- Question 3
  mov di, bp ; Destination Index
  ; Remember, those were just a `ds = ax; ex = bx;` etc.  What values were the registers on the right?

  ; So now we've covered just about all the registers we can, let's start doing some things.

; New function
new_function:
  ; As you can see, it's not really a new function... Since whitespace and labels are effectively ignored, I'm just labeling a new spot in the source file.

  ; Goal: Let's print some text!

  ; First things first, we need to setup the screen such that it will allow us to display text..
  mov ax, 0x0003
  int 0x10          ; AH! Something new!

  ; Step two, a problem: we can only print one letter at a time, like so:
  mov al, 't'
  mov ah, 0x0e      ; <- question 4
  int 0x10          ; The same new thing. Scawy!

  ; `int` is an interrupt.  To step back and think in terms of what the code we programmers write can do, there is nothing the code can do except for manipulate data and make decisions (branching).
    ; If we want any code we write to have meaning impact though, we need to interact with the environment - to manifest the data we manipulate in the code such that it is useful for the end user.
    ; This means we have call into the API of the system our code is running on.  In the of this code, we need to interact with the motherboard's system - the BIOS - and ask it to interact with, on our behalf, the screen (and later maybe other things like USB drives and such).
  ; The interrupt we are using here is interrupt 0x10.  You can read about all the things it does [here](https://en.wikipedia.org/wiki/INT_10H)  But, effectively, there are a number of different things this interrupt can do depending on the value of AH.  AH + 0x0e allows us to print the 8-bit ASCII letter stored in the low 8-bit portion of the a register: al.

  ; But this is kinda useless for us.  It only prints one letter.  We can do better.

  ; First let's define a string to print, but remember...now we're defining junk data in the middle of code, so we need to jump around it so there's no attempt to decode our text string
  mov ax, .string_to_print
  jmp print_string
  .string_to_print: db "acOS", 0x0a, 0x0d, "  by Elyk", 0x00  ; label: <size-of-elements> <array-of-elements>
  ; db stands for define-bytes, there's db, dw, dd, dq, dt, do, dy, and dz.  I just learned that three of those exist.  It's not really assembly-specific knowledge. It's okay.  https://www.nasm.us/doc/nasmdoc3.html
    ; The array can be in the form of a "string" or comma,separate,values,.

; Now let's make a whole 'function' that prints a string
print_string:
  .init:
    mov si, ax  ; We have no syntactic way of passing parameters, so I'm just going to pass the first argument of a function through ax - the string to print.

  .print_char_loop:
    cmp byte [si], 0  ; The brackets around an expression is interpreted as "the address of" whatever that expression is.. It's exactly the same as the dereference operator in C-like languages
                        ; So in this case, si is a pointer (which is a copy of the pointer from ax (line 183), which is the first "argument" to this "function", which is the pointer to the string we are trying to print)
                        ; If we are currently pointing at a null-byte, we have the end of the string... Using null-terminated strings (the zero at the end of the string definition at line 178)
    je .end
   
    mov al, [si]  ; Since this is treated as a dereference of si, we are getting the BYTE AT si... `al = *si`

    mov ah, 0x0e  ; <- Question 5!
    int 0x10      ; Actually print the character
 
    inc si        ; Increment the pointer, get to the next character
    jmp .print_char_loop
    .end:

print_string_right:
  ; Print strings the right way

  jmp .past_data  ; Reminder: Locally-defined lable, also remember: jumping past junk data below
  .important_string_to_print: db "lol kek ", 0
  .past_data:

  mov bp, .important_string_to_print  ; Pointer to string
  mov dh, 3   ; Row to start print on
  mov dl, 15  ; Col to start print on
  mov cx, 0x0007   ; String length
  mov bx, 0000000000001111b  ; White text on black background

  mov ax, 0x1301  ; This one prints a whole string! (also clearing all but the low bit...the coloring mode)
  int 0x10  ; Do the thing

  ; Although to be entirely honest I kinda like printing letter-by-letter more... It's more aesthetic.  Plus you could use interrupt 0x15 to sleep a little bit between each layer and make it look cool...

load_second_stage:
  ; This bit calls another interrupt that uses a file-descriptor-like thing, a daps, to find a load a file from disk.
  ; Load the rest of the bootloader
  mov si, daps ; disk packet address
  mov ah, 0x42 ; al unused
  mov dl, 0x80 ; what to copy
  int 0x13     ; do it (the interrupt takes care of the file loading)

  ; There's one more thing I have to show you before actually leaving here on a good concious : the stack
  ; Let's make a print-number function real quick (and skip over it to the code that uses it)
  jmp stack_example

; This function should print the number stored in AX...this is a non-trivial task, it turns out
newline: 
  db 0x0d, 0x0a
print_buf:
  resb 5
  db ' ', 0
print_rax:
  lea si, [print_buf + 4]       ; our strategy is to build the string of numbers from right to left, using modulo by 10 math, so we're getting to the end of our buffer
  ; I guess it's also worth mentioning what this magical `lea` opcode does... It's sorta witchcraft.
  ; Inside of `[...]` you can have at worst `[reg_1+reg_2*const_1*const_2]`
    ; Where `reg_1` is called the `base`
    ; Where `reg_2` is called the `index`
    ; Where `const_1` is called the `offset`
    ; Where `const_2` is called the `scale`
  ; Whereas most of the time, the brackets serve as a dereference, `lea` explicitly instead just grabs the result of the operation inside the brackets.. Can be used as a shortcut/not having to call `add`
  ; Basically `r9 = print_buf + 18`

  mov di, si                    ; copy the address of the last character
  mov bx, 10                    ; As I said before, we'll be dividing by 10 (which I'm just storing in the B register) to get each lowest digit

  .div_loop:
    ; Division is a little weird in assembly.. But also really nice.
    ; The command to divide is simply `div opcode_1`, where it divides the value in the a register implicitly
    ; The result of the division is stored in rax, and the remainder is stored in rdx.  rdx needs to be cleared before we can actually perform the division, though.
    xor dx, dx                    ; zero rdx for div
    div bx                        ; rax:rdx (result:remainder) = rax / rbx
    add dx, 0x30                  ; convert binary digit to ascii (0x30 = '0')
    mov byte [si], dl             ; save remainder
    dec si                        ; decrement the buffer address, go to the "next" character
    cmp ax, 0                     ; if rax == 0 exit the loop...if we have exhausted the numberspace
    jz .check_buf
    jmp .div_loop

  .check_buf:
    cmp si, di                    ; Compare what we were using as the pointer into our buffer to the saved last byte (check if we did any work)
    jne .print_buf
    mov byte [si], '0'            ; place a zero into the buffer if we didn't do anything else to the buffer
    dec si

  .print_buf:
    ; Initialize Registers
    inc si                        ; address of last digit saved to buffer

    .print_char_loop:
      cmp byte [si], 0           ; Check if we are at the end of the buffer
      je .end

      ; sleep between outputs because I'm 3dGY and C00l
      push cx
        push dx
          push ax
            xor cx, cx
            mov dx, 0xffff
            mov ah, 0x86
            int 0x15
          pop ax
        pop dx
      pop cx

      mov al, [si]               ; Go to the next character

      mov ah, 0x0e                ; Actually print the character
      int 0x10
  
      inc si
      jmp .print_char_loop
.end:
ret

print_info:
  mov ax, bp  ; Print stack registers
  call print_rax
  mov ax, sp
  call print_rax
ret

stack_example:
  mov ax, 1
  push ax  ; Pushes the value onto the stack, saving it
    call print_rax  ; Oh yeah BTW we DO have functions! And this is how you call them... It saves `ip`, the instruction pointer that I mentioned earlier, such that it may be recovered later and we can pick up from right after this call (via the use of a RET opcode)
    call print_info  ; Watch the two values of printed in print_info... One stays the same while the other changes.

      mov ax, 2
      push ax
        call print_rax
        call print_info  ; The BP register, or base pointer isn't changing

        mov ax, 3
        push ax
          call print_rax 
          call print_info  ; The SP register, or stack pointer, however is changing

          mov ax, 4
          push ax
            call print_rax
            call print_info

            mov ax, 5
            push ax
              call print_rax
              call print_info

          pop ax  ; Restores the last value from the stack (First-in-last-out)
          call print_rax
          call print_info  ; And as we take things back off the stack, the sp goes back to what it was!

        pop ax
        call print_rax
        call print_info

      pop ax
      call print_rax
      call print_info  ; One can use this distance - between bp and sp - to set up a local "frame" in the stack to store variables.  This is called a stack frame.  It's a good way to store extra values.

    pop ax
    call print_rax
    call print_info  ; As a matter of fact, compilers store all of a function's local variables in the stack.

  pop ax
  call print_rax
  call print_info


end:
  ; Before we leave this stage, and the w0dERful souRCE cod3 I've WRItten bY HanD, I want to thank you for coming to CSAW and reading this..
  ; I hope that you enjoy the rest of the game, and come to find a deep love for assembly, reverse engineering, and -w-i-s-h-i-n-g- -y-o-u- -n-e-v-e-r- -h-a-d- -e-y-e-s-.
  ; Remember: Google, Stack-Overflow, Manuals, Reference Docs, Wikipedia, etc are all your friend.. This in particular might be helpful: nasm.us/doc/nasmdoci.html (documentation for the assembler I'm using, NASM... Has a nice guide to all this in there)

  ; Now time to scale up our system from 16-bit mode to 64! We're gonna see a couple changes.  The biggest is that we have new registers:
  ; 
  ; The A-D registers are extended to 64, but only gives you access to either the whole thing or the LOW 32 bits (in addition to what we already have)
  ;   RAX = all 64 bits of A
  ;   EAX = Low 32 bits of A
  ;    AX = Low 16 bits of A
  ;    AL = Low 8  bits of A
  ;    AH = 8 bits of A, 8 bits up from the bottom
  ;   Modifying any of these affects the rest, with the caveat that `mov eax, __` also clears the high 32 bits.
  ;
  ; We also get r8-r15
  ;   R8  = all 64 bits of A
  ;   R8D = Low 32 bits of A
  ;   R8W = Low 16 bits of A
  ;   R8B = Low 8  bits of A
  ;   No access to the 8 bits that live 8 bits from the bottom of the register.

  ; Yeah BTW you're gonna need a disassembler now.......I recommend BinaryNinja.

  ; Jump into the second stage of the bootloader/challenge progression
  jmp LOAD_ADDR

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;       Data Section      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 16

; disk address packet structure
daps:
  .size:             db 0x10
  db 0 ; always 0
  .num_sectors:      dw NUM_SECTORS ; this value come from the environment, see the makefile
  .transfer_buffer:  dd LOAD_ADDR
  .lba_lower:        dd 0x1
  .lba_upper:        dd 0x0

times 0200h - 2 - ($ - $$)  db 0    ; Zerofill up to 510 bytes
dw 0AA55h                           ; Boot Sector signature <- need this for the disk to load