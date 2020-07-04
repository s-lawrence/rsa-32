; Mini 32 bit RSA encryption app
; Allows you to encrypt and decrypt messages
; Assignment 2

.386
.model flat,stdcall
.stack 4096
include irvine32.inc
ExitProcess proto,dwExitCode:dword

.data
	menu                   BYTE "============================",13,10
		                   BYTE "1) Start new encryption",13,10
		                   BYTE "2) Decrypt a message",13,10
		                   BYTE "============================",13,10
		                   BYTE "Enter integer: ", 0
	nprompt                BYTE 13,10,"N= ",0
	eprompt                BYTE 13,10,"e= ",0
	dprompt                BYTE 13,10,"d= ",0
	decryptPrompt          BYTE 13,10,"Hex String= ",0
	endMessagePrompt       BYTE 13,10,"Write down the values for N, e, and d. These will be needed for decryption",13,10
					       BYTE "Below is your encrypted message",13,10,0
	messagePrompt          BYTE "Enter message to encrypt(max 80 characters): "
	messageBuffer          BYTE 80 dup(0)		; Stores message to encrypt
	messageByteCount       DWORD ?			; Stores how many bytes are in messageBuffer
	encryptedMessageBuffer BYTE 400 dup(0)		; Stored hex string of encrypted message to be converted	
	encryptedMessageCount  DWORD ?			; Stores how many bytes are in encryptedMessageBuffer
	encryptedIntBuffer     DWORD 40 dup(0)  	; Stores hex values entered to be decrypted
	decryptedMessageBuffer BYTE 80 dup(0)		; Stores decrypted message
	rsaRange               DWORD 35000		; Sets the limit on rsa values so program does not overflow 32 bits during calculations
	rsaPrime1              DWORD ?			; One of the prime numbers used to calculate N and NPrime, denoted as p usually
	rsaPrime2              DWORD ?			; One of the prime numbers used to calculate N and NPrime, denoted as n usually
	N                      DWORD ?			; Mod value used in rsa encryption and decryption
	NPrime                 DWORD ?			; N Prime used to calculate e (exponent) for rsa encryption
	e                      DWORD ?			; Exponent used for rsa encryption
	d                      DWORD ?			; Exponent used for rsa decryption, multiplicative inverse of e mod NPrime
	x                      DWORD ?			; global variable for fullGcd
	y                      DWORD ?			; global variable for fullGcd
.code


isqrt proc num:dword					; this square root process was found at 
        mov     eax, num				; https://codereview.stackexchange.com/questions/48847/integer-square-root-in-x86-assembly-nasm
        xor     ebx, ebx
        bsr     ecx, eax
        and     cl, 0feh
        mov     edx, 1
        shl     edx, cl
refine:
        mov     esi, ebx
        add     esi, edx
        cmp     esi, eax
        ja      @f
        sub     eax, esi
        shr     ebx, 1
        add     ebx, edx
        jmp     next
@@:
        shr     ebx, 1
next :
        shr     edx, 2
        jnz     refine
        mov     eax, ebx
        ret
isqrt endp




getPrimeNumber proc range:dword				; This process retrieves a random prime number 
.data							; between 1 and the range value passed to it
	tempPrime        DWORD ?			; returns in eax 
	tempPrimeSqrt    DWORD ?
.code
getPrime:
	mov     eax,range
	call    RandomRange
	mov     tempPrime, eax
	push    eax
	call    isqrt
	mov     tempPrimeSqrt, eax
	mov     ecx,2
jumpIsPrime:
	xor     edx,edx
	mov     eax, tempPrime
	div     ecx
	mov     eax,0
	cmp     edx,eax
	jz      getPrime
	inc     ecx
	cmp     ecx,tempPrimeSqrt
	jle     jumpIsPrime
	mov     eax, tempPrime
	ret
getPrimeNumber endp

gcd proc var1:dword, var2:dword				; This process calculates the greatest commone
	xor     edx,edx					; denominator for the two operands passed to it
	cmp     edx,var2				; returns in eax
	jnz     recall
	ret
recall:
	mov     eax,var1
	mov     ebx,var2
	div     ebx
	push    edx ;mod of var1 and var2
	push    var2
	call    gcd
	ret
gcd endp

fullGcd proc var1:dword, var2:dword			; This process accepts two DWORDs and 
.data							; is used with the inverse process to return 
	x1     DWORD ?					; the multiplicative inverse of them
	y1     DWORD ?					; returns in eax
.code
	mov     eax,var1
	mov     ebx,var2
	cmp     ebx,0
	jnz     jumpRecall
	mov     x,1
	mov     y,0
	ret
jumpRecall:
	xor     edx,edx
	div     ebx
	push    edx
	push    ebx
	call    fullGcd
	mov     eax,x
	mov     x1,eax
	mov     eax,y
	mov     y1,eax
	mov     eax,y1
	mov     x,eax
	mov     edx,0
	mov     eax,var1
	mov     ebx,var2
	div     ebx
	mul     y1
	mov     ebx,x1
	sub     ebx,eax
	mov     y,ebx
	ret
fullGcd endp

inverse proc var1:dword, var2:dword			; This process accepts two DWORDs and 
	push    var2					; is used with the fullGcd process to return 
	push    var1					; the multiplicative inverse of them
	call    fullGcd					; returns in eax
	mov     eax,x
	cmp     eax,0
	jg      jumpReturnX
	add     eax,var2
	ret
jumpReturnX:
	ret
inverse endp

modPower proc base:dword, exponent:dword, m:dword
.data							; This processs accepts three DWORDs and
	temp    DWORD ?					; calculates the modular exponentiation
.code							; returns in eax
	mov     eax,exponent
	cmp     eax,0
	jnz     jumpRecall
	mov     eax,1
	ret
jumpRecall:
	mov     eax,m
	push    eax					; pushes mod to the stack as third operand for recursive call
	mov     edx,0
	mov     eax,exponent
	mov     ebx,2
	div     ebx				
	push    eax					; pushes exponent divided by two to the stack
	xor     edx,edx
	mov     eax,base
	mul     eax
	mov     ebx,m
	div     ebx
	push    edx					; pushes (base * base) % mod to the stack
	call    modPower				; recursive call
	mov     temp,eax
	xor     edx,edx
	mov     eax,exponent
	mov     ebx,2
	div     ebx	
	cmp     edx,0
	jnz     jumpOddExp
	mov     eax,temp
	ret
jumpOddExp:						; Performs if when the exponent is odd
	xor     edx,edx
	mov     eax,temp
	mov     ebx,base
	mul     ebx
	mov     ebx,m
	div     ebx
	mov     temp,edx
	mov     eax,temp
	ret
modPower endp

main proc
menuPrompt:
	mov     edx, OFFSET menu
	call    WriteString
	call    ReadInt
	cmp     eax, 1
	jz      newEncrypt
	cmp     eax, 2
	jnz     menuPrompt
newDecrypt:
	mov     edx,OFFSET nprompt
	call    WriteString
	call    ReadDec
	mov     N,eax
	mov     edx,OFFSET dprompt
	call    WriteString
	call    ReadDec
	mov     d,eax
	mov     edx,OFFSET decryptPrompt
	call    WriteString
	mov     edx, OFFSET encryptedMessageBuffer
	mov     ecx, SIZEOF encryptedMessageBuffer
	call    ReadString
	mov     encryptedMessageCount,eax
	mov     esi,OFFSET encryptedMessageBuffer
	mov     edi,OFFSET encryptedIntBuffer
	mov     ebx,0
	mov     eax,0
	mov		ecx,0 
WhileDigitD:						; The following ASCII to Hex conversion came from
							; https://stackoverflow.com/questions/16047113/how-do-i-convert-a-string-representing-a-signed-hex-int-into-its-signed-int-doub
    cmp     byte ptr [esi], ' '	
    je      next_char            
	cmp		ecx,8
	jz		next_int
    cmp     BYTE PTR [esi],'0'				; compare next character to '0'
    jb      EndWhileDigitD				; not a digit if smaller than '0'
    cmp     BYTE PTR [esi],'9'				; compare to '9'
    ja      TestForHexD      
    mov     bl,[esi]					; ASCII character to BL
    sub     bl,'0'					; sub bl,30h -> convert ASCII to binary.

shift_eax_by_4_and_add_bl:
    shl     eax,4					; shift the current value 4 bits to left.
    or      al,bl					; add the value of the current digit.
	inc     esi
	add		ecx,1
    jmp     WhileDigitD

next_int:
    ;inc     esi
	mov	    [edi],eax
	add     edi,4
	xor     eax,eax
	xor     ecx,ecx
    jmp     WhileDigitD
next_char:
    inc     esi
    jmp     WhileDigitD

TestForHexD:
    cmp     BYTE PTR [esi], 'A'
    jb      EndWhileDigitD
    cmp     BYTE PTR [esi], 'F'
    ja      EndWhileDigitD
    mov     bl,[esi]
    sub     bl,('A'-0Ah)				; sub bl,55 -> convert ASCII to binary.
    jmp     shift_eax_by_4_and_add_bl
EndWhileDigitD:
	mov     esi,OFFSET encryptedIntBuffer
	mov     edi,OFFSET decryptedMessageBuffer
jumpDecrypt:
	mov     ecx,[esi]
	cmp     ecx,0
	jz      jumpDoneDecryption
	mov     eax,N
	push    eax
	mov     eax,d
	push    eax
	push    ecx
	call    modPower
	mov     [edi],ah
	inc		edi
	mov     [edi],al
	inc		edi
	add     esi,4
	xor     ecx,ecx
	jmp     jumpDecrypt
jumpDoneDecryption:
	mov     edx,OFFSET decryptedMessageBuffer
	call    WriteString				; Output decrypted message
	jmp     jumpEnd
newEncrypt:
	mov     edx, OFFSET messagePrompt
	call    WriteString
	mov     edx,OFFSET messageBuffer
	mov     ecx,SIZEOF messageBuffer
	call    ReadString
	mov     messageByteCount,eax
	mov     eax,rsaRange
	push    eax
	call    getPrimeNumber				; get prime number between 0 and rsaRange
	mov     rsaPrime1, eax
	mov     eax,rsaRange
	push    eax
	call    getPrimeNumber
	mov     rsaPrime2, eax  
	mov     ebx,rsaPrime1
	mul     ebx
	mov     N,eax					; Stores product of rsaPrime1 and rsaPrime2 in N
	mov     eax, rsaPrime1
	sub     eax,1
	mov     ebx, rsaPrime2
	sub     ebx,1
	mul     ebx
	mov     NPrime, eax				; Stores (rsaPrime1 - 1) * (rsaPrime2 - 1) in NPrime
jumpSetE:
	mov     eax, NPrime
	push    eax
	call    getPrimeNumber 				; returns a prime number between 1 and NPrime
	mov     e,eax
	mov     eax,e
	mov     ebx,NPrime
	push    ebx
	push    eax
	call    inverse
	mov     d,eax
	mov     esi,OFFSET messageBuffer 		; load address of message
	mov     edi,OFFSET encryptedIntBuffer 
jumpEncrypt:
	mov     al,[esi]
	cmp     al,0
	jz      jumpDoneEncryption
	mov     ecx,0
	mov     ch,[esi]				; move first letter to ch
	add     esi,1
	mov     cl,[esi]				; move second letter to cl
	add     esi,1
	mov     eax,N
	push    eax
	mov     eax,e
	push    eax
	push    ecx
	call    modPower
	mov     [edi],eax				; move encrypted integer to encryptedIntBuffer
	add     edi,4
	xor     eax,eax
	jmp     jumpEncrypt
jumpDoneEncryption:
	mov     edx,OFFSET nprompt
	call    WriteString
	mov     eax,N
	call    WriteInt
	mov     edx,OFFSET eprompt
	call    WriteString
	mov     eax,e
	call    WriteInt
	mov     edx,OFFSET dprompt
	call    WriteString
	mov     eax,d
	call    WriteInt
	mov     edx, OFFSET endMessagePrompt
	call    WriteString
	mov     esi, OFFSET encryptedIntBuffer
	mov     ebx,TYPE encryptedIntBuffer
	mov     ecx,LENGTHOF encryptedIntBuffer
	call    DumpMem
jumpEnd:

	invoke ExitProcess,0
main endp
end main
