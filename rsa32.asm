TITLE RSA in MASM - Copyright (C) Fabio Banfi 2013-2026

; HOW TO RUN:
;
; First open the x86 Native Tools Command Prompt (requires installing x86/64 build tools from Visual Studio Installer):
; cmd /k "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat"
;
; Then, compile and link:
; ml /c /coff rsa32.asm
; link rsa32.obj kernel32.lib user32.lib msvcrt.lib /SUBSYSTEM:CONSOLE
;
; Or, minimally:
; ml /c rsa32.asm && link rsa32 /SUBSYSTEM:CONSOLE

; Uncomment to use MessageBoxA instead of WriteConsoleA to display the output (use /SUBSYSTEM:WINDOWS):
; MSGBOX EQU 1

.686P
.MODEL FLAT, STDCALL
OPTION CASEMAP:NONE

INCLUDELIB kernel32
INCLUDELIB user32
INCLUDELIB msvcrt

EXTERN wsprintfA:PROC

ExitProcess PROTO STDCALL :DWORD
IFDEF MSGBOX
MessageBoxA PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD
ELSE
STD_OUTPUT_HANDLE equ -11
lstrlenA PROTO STDCALL :DWORD
GetStdHandle PROTO STDCALL :DWORD
WriteConsoleA PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ENDIF

.DATA
rsa_sz_title DB "RSA", 0                    ; The MessageBox title.
IFDEF MSGBOX
rsa_sz_fmt db "%u", 0                       ; Format string for wsprintfA
ELSE
rsa_sz_fmt db "%u", 13, 10, 0               ; Format string for WriteConsoleA
ENDIF

.DATA?
rsa_sz_text DB 32 DUP (?)                   ; The MessageBox message.
rsa_dw_n DD ?                               ; The public modulo.
rsa_dw_e DD ?                               ; The public key e.
rsa_dw_d DD ?                               ; The private key d.

.CODE

; Programs's entry point.
start:
        call    rsa_init                    ; Initialize RSA data.
        push    42                          ; Push test number 42 on the stack.
        call    rsa_encrypt                 ; Encrypt 42.
        push    eax                         ; Push encrypted value on the stack.
        call    rsa_decrypt                 ; Decrypt encrypted value.
        call    rsa_print_int               ; Display the decrypted value.
        call    rsa_clear                   ; Clear RSA data.
        push    0                           ; Push argument of ExitProcess on the stack.
        call    ExitProcess                 ; Exit program.

; Generate public and private keys.
rsa_init:
        pushad                              ; Backup all general purpose registers on the stack.
rsa_init_gen_p:
        rdtsc                               ; Get the cpu time stamp counter as random number on eax.
        or      eax, 1                      ; Make sure eax is odd.
        and     eax, 0ffffh                 ; Bitmask to make sure p is smaller than 2^16, so that n is at most 32 bits.
        mov     ebx, eax                    ; Store p in ebx.
        call    rsa_is_prime                ; Check whether p is prime.
        cmp     eax, 0                      ; Check whether primality test succeeded.
        je      rsa_init_gen_p              ; Repeat until p is prime.
rsa_init_gen_q:
        rdtsc                               ; Get the cpu time stamp counter as random number on eax.
        or      eax, 1                      ; Make sure eax is odd.
        and     eax, 0ffffh                 ; Bitmask to make sure q is smaller than 2^16, so that n is at most 32 bits.
        mov     ecx, eax                    ; Store q in ecx.
        call    rsa_is_prime                ; Check whether q is prime.
        cmp     eax, 0                      ; Check whether primality test succeeded.
        je      rsa_init_gen_q              ; Repeat until q is prime.
        mov     eax, ebx                    ; Copy p from ebx back to eax.
        mul     ecx                         ; Multiply p by q and store result in eax.
        mov     [rsa_dw_n], eax             ; Save n = p * q to memory.
        dec     ebx                         ; Set ebx to p - 1.
        dec     ecx                         ; Set ecx to q - 1.
        mov     eax, ebx                    ; Move p - 1 to accumulator.
        mul     ecx                         ; Now eax contains t = (p - 1) * (q - 1) = phi(n).
        mov     ebx, 65537                  ; Use 65537 as public exponent e and store it in ebx.
        mov     ecx, eax                    ; Copy t to ecx.
        call    rsa_ext_euclid              ; Set m = e in ebx, n = t in eax and get multiplicative inverse d of e modulo t in eax.
        cmp     eax, 0                      ; Check whether d > 0.
        jg      rsa_init_end                ; If d > 0 there is no need to make it positive.
        add     eax, ecx                    ; Make sure d is positive, hence d := d + t.
rsa_init_end:
        mov     [rsa_dw_e], 65537           ; Save e to memory.
        mov     [rsa_dw_d], eax             ; Save d to memory.
        popad                               ; Restore all general purpose registers from the stack.
        ret                                 ; Give control back to the caller.

; Clear public and private keys.
rsa_clear:
        mov     [rsa_dw_n], 0               ; Remove modulo n from memory.
        mov     [rsa_dw_e], 0               ; Remove public exponent e from memory.
        mov     [rsa_dw_d], 0               ; Remove private exponent d from memory.
        ret                                 ; Give control back to the caller.

; Encrypt 32 bits message m.
rsa_encrypt:
        push    ebp                         ; Save the old base pointer value.
        mov     ebp, esp                    ; Set the new base pointer value.
        push    ebx                         ; Backup ebx on the stack.
        push    esi                         ; Backup esi on the stack.
        mov     ebx, 8[ebp]                 ; Load message m from the stack to register.
        mov     esi, [rsa_dw_n]             ; Load n from memory to register.
        mov     ecx, [rsa_dw_e]             ; Load e from memory to register.
        call    rsa_mod_exp                 ; Compute m^e mod n.
        pop     esi                         ; Restore esi from the stack.
        pop     ebx                         ; Restore ebx from the stack.
        mov     esp, ebp                    ; Deallocate local variables.
        pop     ebp                         ; Restore the caller's base pointer value.
        ret                                 ; Give control back to the caller.

; Decrypt 32 bits ciphertext c.
rsa_decrypt:
        push    ebp                         ; Save the old base pointer value.
        mov     ebp, esp                    ; Set the new base pointer value.
        push    ebx                         ; Backup ebx on the stack.
        push    esi                         ; Backup esi on the stack.
        mov     ebx, 8[ebp]                 ; Load ciphertext c from the stack to register.
        mov     esi, [rsa_dw_n]             ; Load n from memory to register.
        mov     ecx, [rsa_dw_d]             ; Load d from memory to register.
        call    rsa_mod_exp                 ; Compute c^d mod n.
        pop     esi                         ; Restore esi from the stack.
        pop     ebx                         ; Restore ebx from the stack.
        mov     esp, ebp                    ; Deallocate local variables.
        pop     ebp                         ; Restore the caller's base pointer value.
        ret                                 ; Give control back to the caller.

; Modular exponentiation (eax = b^e mod m), expects b in ebx, e in ecx and m in esi.
rsa_mod_exp:
        push    edi                         ; Backup edi on the stack.
        mov     edi, 1                      ; Set c := 1.
rsa_mod_exp_loop:
        cmp     ecx, 0                      ; Compare e with 0.
        jz      rsa_mod_exp_end             ; If e == 0 return c (treat exponent as unsigned).
        mov     edx, ecx                    ; Copy e to edx.
        and     edx, 1                      ; Set edx to e & 1.
        cmp     edx, 0                      ; Compare e with 0.
        je      rsa_mod_exp_skip            ; If e & 1 = 0 skip.
        mov     eax, edi                    ; Move c to accumulator.
        mul     ebx                         ; Set extended register edx:eax to b * c (multiplication result may actually be more than 32 bit).
        div     esi                         ; Divide edx:eax (b * c) by esi (m) and put result in eax (b * c / m) and remainder in edx (b * c mod m).
        mov     edi, edx                    ; Copy c back to edi.
rsa_mod_exp_skip:
        shr     ecx, 1                      ; Divide exponent e by 2, that is e := e >> 1.
        mov     eax, ebx                    ; Move b to accumulator.
        mul     ebx                         ; Set extended register edx:eax to b * b (multiplication result may actually be more than 32 bit).
        div     esi                         ; Divide edx:eax (b * b) by esi (m) and put result in eax (b  *b / m) and remainder in edx (b * b mod m).
        mov     ebx, edx                    ; Copy b back to ebx.
        jmp     rsa_mod_exp_loop            ; Repeat.
rsa_mod_exp_end:
        mov     eax, edi                    ; Move return value c to eax.
        pop     edi                         ; Restore edi from the stack.
        ret                                 ; Give control back to the caller.

; Extended euclidean algorithm, find x, y (eax, ebx) given m, n (ebx, eax) s.t. m * x + n * y = gcd(m, n).
rsa_ext_euclid:
        push    ecx                         ; Backup ecx on the stack.
        xor     edx, edx                    ; Register edx must be 0 because div takes edx:eax.
        idiv    ebx                         ; Divide edx:eax (n) by ebx (m) and put result in eax (n / m) and remainder in edx (n mod m).
        cmp     edx, 0                      ; Compare m with 0.
        je      rsa_ext_euclid_return       ; If n mod m = 0 return (1, 0).
        mov     ecx, eax                    ; store n/m in ecx
        mov     eax, ebx                    ; n = m
        mov     ebx, edx                    ; m = n mod m
        call    rsa_ext_euclid              ; Recursive call with m = n mod m, n = m, x', y'.
        mov     esi, eax                    ; Store x' to esi.
        imul    ecx                         ; Put x' * (n / m) in eax.
        sub     ebx, eax                    ; Put y' - x' * (n / m) in ebx.
        mov     eax, ebx                    ; Put x = y' - x' * (n / m) in eax.
        mov     ebx, esi                    ; Put y = x' in ebx.
        jmp     rsa_ext_euclid_end          ; End of the algorithm.
rsa_ext_euclid_return:
        mov     eax, 1                      ; Return x = 1.
        mov     ebx, 0                      ; Return y = 0.
rsa_ext_euclid_end:
        pop     ecx                         ; Restore ecx from the stack.
        ret                                 ; Give control back to the caller.

; Primality test for n (eax) odd and larger than 3, returns true or false in eax.
rsa_is_prime:
        push    ebx                         ; Backup ebx on the stack.
        push    ecx                         ; Backup ecx on the stack.
        push    edx                         ; Backup edx on the stack.
        cmp     eax, 2                      ; Compare n with 2.
        jb      rsa_is_prime_false          ; If n less than 2, return false.
        je      rsa_is_prime_true           ; If n is 2, return true.
        test    eax, 1                      ; Check lsb of n.
        jz      rsa_is_prime_false          ; If n is even, return false.
        push    eax                         ; Push n on the stack.
        fild    DWORD PTR [esp]             ; Move n from the stack to ST(0) in FPU.
        fsqrt                               ; Perform ST(0) = sqrt(ST(0)) in FPU.
        fistp   DWORD PTR [esp]             ; Move sqrt(n) from ST(0) to the stack.
        pop     ecx                         ; Pop sqrt(n) to the counter.
        or      ecx, 1                      ; Make sure counter is odd.
        mov     ebx, eax                    ; Copy n to ebx.
rsa_is_prime_loop:
        xor     edx, edx                    ; Register edx must be 0 because div takes edx:eax.
        mov     eax, ebx                    ; Copy n back to eax.
        div     ecx                         ; Divide edx:eax by ecx and put result in eax and remainder in edx.
        cmp     edx, 0                      ; Compare edx with 0.
        je      rsa_is_prime_false          ; If remainder is zero return false.
        sub     ecx, 2                      ; Decrease i by 2.
        cmp     ecx, 3                      ; Compare i with 3.
        jge     rsa_is_prime_loop           ; Repeat until i = 3.
rsa_is_prime_true:
        mov     eax, 1                      ; Set return value to true.
        jmp     rsa_is_prime_end            ; Return.
rsa_is_prime_false:
        mov     eax, 0                      ; Set return value to false.
rsa_is_prime_end:
        pop     edx                         ; Restore edx from the stack.
        pop     ecx                         ; Restore ecx from the stack.
        pop     ebx                         ; Restore ebx from the stack.
        ret                                 ; Give control back to the caller.
        
; Display content of eax as integer in a messagebox.
rsa_print_int:
        pushad                              ; Backup all general purpose registers on the stack.
        push    eax                         ; Third argument of wsprintfA: number to be converted.
        push    offset rsa_sz_fmt           ; Second argument of wsprintfA: format string "%d".
        push    offset rsa_sz_text          ; First argument of wsprintfA: address of destination string.
        call    wsprintfA                   ; Convert eax to its string representation.
        add     esp, 12                     ; C calling convention, clean wsprintfA's stack.
        IFDEF MSGBOX
        xor     eax, eax                    ; Set eax to 0.
        push    eax                         ; Push 0 as fourth argument of MessageBox on the stack.
        push    offset rsa_sz_title         ; Push rsa_sz_title address as third argument of MessageBox on the stack.
        push    offset rsa_sz_text          ; Push rsa_sz_text address as second argument of MessageBox on the stack.
        push    eax                         ; Push 0 as first argument of MessageBox on the stack.
        call    MessageBoxA                 ; Call window' MessageBox function.
        ELSE
        push    offset rsa_sz_text          ; Push address of string to be printed as second argument of WriteConsoleA on the stack.
        call    lstrlenA                    ; Get the length of the string to be printed in eax.
        mov     ecx, eax                    ; Copy the length of the string to ecx.
        push    0                           ; Push 0 as fifth argument of WriteConsoleA on the stack, that is lpReserved which must be NULL.
        push    0                           ; Push 0 as fourth argument of WriteConsoleA on the stack, that is lpNumberOfCharsWritten which must be NULL.
        push    ecx                         ; Push the length of the string as third argument of WriteConsoleA on the stack, that is nNumberOfCharsToWrite.
        push    offset rsa_sz_text          ; Push the address of the string as second argument of WriteConsoleA on the stack, that is lpBuffer.
        push    -11                         ; Push -11 as first argument of WriteConsoleA on the stack, that is STD_OUTPUT_HANDLE.
        call    GetStdHandle                ; Get the handle of the standard output device in eax.
        push    eax                         ; Push the handle of the standard output device as first argument of WriteConsoleA on the stack.
        call    WriteConsoleA               ; Call WriteConsoleA to print the string to the console.
        ENDIF
        popad                               ; Restore all general purpose registers from the stack.
        ret                                 ; Give control back to the caller.

END start

