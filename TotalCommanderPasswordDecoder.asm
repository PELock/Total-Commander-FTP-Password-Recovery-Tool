;////////////////////////////////////////////////////////////////////////////////
;//
;// Total Commander FTP Password Recovery Algorithm
;//
;// Bartosz Wójcik
;//
;// https://www.pelock.com/products/total-commander-ftp-password-recovery
;//
;////////////////////////////////////////////////////////////////////////////////

.data?

        magic   dd ?

.code

DecodePassword proc near

        mov     eax,password     ; password
        test    eax,eax          ; if there's no password (anonymous connection?)
        je      @decode_end      ; dont do anything
        call    @decode          ; decrypt password
        jmp     @decode_end      ; return from the procedure

@decode:
        push    ebp
        mov     ebp, esp
        add     esp, 0FFFFFEE8h
        push    ebx
        push    esi
        push    edi
        mov     esi, eax

        lea     eax, [ebp-118h]
        mov     edx, esi
        call    @loc_406BB0
        mov     eax, esi
        call    @loc_406B48
        shr     eax, 1
        dec     eax
        mov     [ebp-8], eax
        cmp     dword ptr [ebp-8], 4
        jge     @loc_47806B
        mov     byte ptr [esi], 0
        jmp     @loc_4781E4

@loc_47806B:
        lea     eax, [ebp-118h]
        mov     [ebp-14h], eax
        mov     edi, [ebp-8]
        test    edi, edi
        jl      @loc_478091
        inc     edi
        xor     ebx, ebx

        push    edx

@loc_47807E:
        mov     eax, [ebp-14h]

        mov     dx,word ptr[eax]

        mov     al,dl

        sub     al,'0'
        db      0D4h,10h
        db      0D5h,09h

        shl     al,4

        mov     dl,al
        mov     al,dh

        sub     al,'0'
        db      0D4h,10h
        db      0D5h,09h

        add     al,dl

        mov     [esi+ebx], al
        add     dword ptr [ebp-14h], 2
        inc     ebx
        dec     edi
        jnz     @loc_47807E

        pop     edx

@loc_478091:
        mov     eax, [ebp-8]
        mov     al, [esi+eax-3]
        mov     [ebp-0Ch], al
        mov     eax, [ebp-8]
        mov     al, [esi+eax-2]
        mov     [ebp-0Bh], al
        mov     eax, [ebp-8]
        mov     al, [esi+eax-1]
        mov     [ebp-0Ah], al
        mov     eax, [ebp-8]
        mov     al, [esi+eax]
        mov     [ebp-9], al
        sub     dword ptr [ebp-8], 4
        mov     eax, [ebp-8]
        mov     byte ptr [esi+eax+1], 0
        mov     dword ptr[magic], 0CF671h
        mov     edi, [ebp-8]
        test    edi, edi
        jl      @loc_47810D
        inc     edi
        xor     ebx, ebx

@loc_4780D8:
        xor     eax, eax
        mov     al, [esi+ebx]
        mov     [ebp-4], ax
        mov     eax, 8
        call    @loc_402A9C
        mov     [ebp-1], al
        push    ax
        push    cx
        mov     cl, [ebp-1]
        mov     ax, [ebp-4]
        rol     al, cl
        mov     [ebp-4], ax
        pop     cx
        pop     ax
        mov     al, [ebp-4]
        mov     [esi+ebx], al
        inc     ebx
        dec     edi
        jnz     @loc_4780D8

@loc_47810D:
        mov     dword ptr[magic], 3039h
        mov     ebx, 100h

@loc_47811C:
        mov     edi, [ebp-8]
        inc     edi
        mov     eax, edi
        call    @loc_402A9C
        lea     eax, [esi+eax]
        push    eax
        mov     eax, edi
        call    @loc_402A9C
        lea     eax, [esi+eax]
        pop     edx
        call    @loc_478020
        dec     ebx
        jnz     @loc_47811C
        mov     dword ptr[magic], 0A564h
        mov     edi, [ebp-8]
        test    edi, edi
        jl      @loc_478173
        inc     edi
        xor     ebx, ebx

@loc_478152:
        xor     eax, eax
        mov     al, [esi+ebx]
        mov     [ebp-4], ax
        mov     eax, 100h
        call    @loc_402A9C
        xor     [ebp-4], ax
        mov     al, [ebp-4]
        mov     [esi+ebx], al
        inc     ebx
        dec     edi
        jnz     @loc_478152

@loc_478173:
        mov     dword ptr[magic], 0D431h
        mov     edi, [ebp-8]
        test    edi, edi
        jl      @loc_4781C4
        inc     edi
        xor     ebx, ebx

@loc_478187:
        xor     eax, eax
        mov     al, [esi+ebx]
        mov     [ebp-4], ax
        mov     eax, 100h
        call    @loc_402A9C
        movzx   edx, word ptr [ebp-4]
        add     edx, 100h
        sub     edx, eax
        and     edx, 800000FFh
        jns     @loc_4781B6
        dec     edx
        or      edx, 0FFFFFF00h
        inc     edx

@loc_4781B6:
        mov     [ebp-4], dx
        mov     al, [ebp-4]
        mov     [esi+ebx], al
        inc     ebx
        dec     edi
        jnz     @loc_478187

@loc_4781C4:
        mov     dword ptr [ebp-10h], 0FFFFFFFFh
        lea     ecx, [ebp-10h]
        mov     edx, [ebp-8]
        inc     edx
        mov     eax, esi
        call    @sub_530E28
        mov     eax, [ebp-0Ch]
        cmp     eax, [ebp-10h]
        jz      @loc_4781E4
        mov     byte ptr [esi], 0

@loc_4781E4:
        pop     edi
        pop     esi
        pop     ebx
        mov     esp, ebp
        pop     ebp
        ret

@loc_406BB0:
        push    edi
        push    esi
        mov     esi, eax
        mov     edi, edx
        or      ecx, -1
        xor     al, al
        repne scasb
        not     ecx
        mov     edi, esi
        mov     esi, edx
        mov     edx, ecx
        mov     eax, edi
        shr     ecx, 2
        rep movsd
        mov     ecx, edx
        and     ecx, 3
        rep movsb
        pop     esi
        pop     edi
        ret

@loc_406B48:
        mov     edx, edi
        mov     edi, eax
        or      ecx, -1
        xor     al, al
        repne scasb
        mov     eax, 0FFFFFFFEh
        sub     eax, ecx
        mov     edi, edx
        ret

@loc_402A9C:
        imul    edx, dword ptr[magic], 8088405h
        inc     edx
        mov     dword ptr[magic], edx
        mul     edx
        mov     eax, edx
        ret

@loc_478020:
        push    ebx
        mov     cl, [eax]
        mov     bl, [edx]
        mov     [eax], bl
        mov     [edx], cl
        pop     ebx
        ret


@sub_530E28:
        push    ebp
        mov     ebp, esp
        add     esp, 0FFFFFFF4h
        mov     [ebp-8], ecx
        mov     [ebp-0Ch], edx
        mov     [ebp-4], eax
        push    edi
        push    esi
        push    ebx
        mov     edi, [ebp-4]
        mov     eax, [ebp-8]
        mov     eax, [eax]
        mov     esi, offset @magic_table
        mov     ecx, [ebp-0Ch]
        or      ecx, ecx
        jz      @loc_530E62

@loc_530E4F:
        xor     ebx, ebx
        mov     bl, al
        shr     eax, 8
        xor     bl, [edi]
        inc     edi
        shl     ebx, 2
        xor     eax, [esi+ebx]
        dec     ecx
        jnz     @loc_530E4F

@loc_530E62:
        mov     ebx, [ebp-8]
        mov     [ebx], eax
        pop     ebx
        pop     esi
        pop     edi
        mov     esp, ebp
        pop     ebp
        ret

@magic_table:   db 0,0,0,0,150,48,7,119,44,97,14,238,186,81,9,153
                db 25,196,109,7,143,244,106,112,53,165,99,233,163,149,100,158
                db 50,136,219,14,164,184,220,121,30,233,213,224,136,217,210,151
                db 43,76,182,9,189,124,177,126,7,45,184,231,145,29,191,144
                db 100,16,183,29,242,32,176,106,72,113,185,243,222,65,190,132
                db 125,212,218,26,235,228,221,109,81,181,212,244,199,133,211,131
                db 86,152,108,19,192,168,107,100,122,249,98,253,236,201,101,138
                db 79,92,1,20,217,108,6,99,99,61,15,250,245,13,8,141
                db 200,32,110,59,94,16,105,76,228,65,96,213,114,113,103,162
                db 209,228,3,60,71,212,4,75,253,133,13,210,107,181,10,165
                db 250,168,181,53,108,152,178,66,214,201,187,219,64,249,188,172
                db 227,108,216,50,117,92,223,69,207,13,214,220,89,61,209,171
                db 172,48,217,38,58,0,222,81,128,81,215,200,22,97,208,191
                db 181,244,180,33,35,196,179,86,153,149,186,207,15,165,189,184
                db 158,184,2,40,8,136,5,95,178,217,12,198,36,233,11,177
                db 135,124,111,47,17,76,104,88,171,29,97,193,61,45,102,182
                db 144,65,220,118,6,113,219,1,188,32,210,152,42,16,213,239
                db 137,133,177,113,31,181,182,6,165,228,191,159,51,212,184,232
                db 162,201,7,120,52,249,0,15,142,168,9,150,24,152,14,225
                db 187,13,106,127,45,61,109,8,151,108,100,145,1,92,99,230
                db 244,81,107,107,98,97,108,28,216,48,101,133,78,0,98,242
                db 237,149,6,108,123,165,1,27,193,244,8,130,87,196,15,245
                db 198,217,176,101,80,233,183,18,234,184,190,139,124,136,185,252
                db 223,29,221,98,73,45,218,21,243,124,211,140,101,76,212,251
                db 88,97,178,77,206,81,181,58,116,0,188,163,226,48,187,212
                db 65,165,223,74,215,149,216,61,109,196,209,164,251,244,214,211
                db 106,233,105,67,252,217,110,52,70,136,103,173,208,184,96,218
                db 115,45,4,68,229,29,3,51,95,76,10,170,201,124,13,221
                db 60,113,5,80,170,65,2,39,16,16,11,190,134,32,12,201
                db 37,181,104,87,179,133,111,32,9,212,102,185,159,228,97,206
                db 14,249,222,94,152,201,217,41,34,152,208,176,180,168,215,199
                db 23,61,179,89,129,13,180,46,59,92,189,183,173,108,186,192
                db 32,131,184,237,182,179,191,154,12,226,182,3,154,210,177,116
                db 57,71,213,234,175,119,210,157,21,38,219,4,131,22,220,115
                db 18,11,99,227,132,59,100,148,62,106,109,13,168,90,106,122
                db 11,207,14,228,157,255,9,147,39,174,0,10,177,158,7,125
                db 68,147,15,240,210,163,8,135,104,242,1,30,254,194,6,105
                db 93,87,98,247,203,103,101,128,113,54,108,25,231,6,107,110
                db 118,27,212,254,224,43,211,137,90,122,218,16,204,74,221,103
                db 111,223,185,249,249,239,190,142,67,190,183,23,213,142,176,96
                db 232,163,214,214,126,147,209,161,196,194,216,56,82,242,223,79
                db 241,103,187,209,103,87,188,166,221,6,181,63,75,54,178,72
                db 218,43,13,216,76,27,10,175,246,74,3,54,96,122,4,65
                db 195,239,96,223,85,223,103,168,239,142,110,49,121,190,105,70
                db 140,179,97,203,26,131,102,188,160,210,111,37,54,226,104,82
                db 149,119,12,204,3,71,11,187,185,22,2,34,47,38,5,85
                db 190,59,186,197,40,11,189,178,146,90,180,43,4,106,179,92
                db 167,255,215,194,49,207,208,181,139,158,217,44,29,174,222,91
                db 176,194,100,155,38,242,99,236,156,163,106,117,10,147,109,2
                db 169,6,9,156,63,54,14,235,133,103,7,114,19,87,0,5
                db 130,74,191,149,20,122,184,226,174,43,177,123,56,27,182,12
                db 155,142,210,146,13,190,213,229,183,239,220,124,33,223,219,11
                db 212,210,211,134,66,226,212,241,248,179,221,104,110,131,218,31
                db 205,22,190,129,91,38,185,246,225,119,176,111,119,71,183,24
                db 230,90,8,136,112,106,15,255,202,59,6,102,92,11,1,17
                db 255,158,101,143,105,174,98,248,211,255,107,97,69,207,108,22
                db 120,226,10,160,238,210,13,215,84,131,4,78,194,179,3,57
                db 97,38,103,167,247,22,96,208,77,71,105,73,219,119,110,62
                db 74,106,209,174,220,90,214,217,102,11,223,64,240,59,216,55
                db 83,174,188,169,197,158,187,222,127,207,178,71,233,255,181,48
                db 28,242,189,189,138,194,186,202,48,147,179,83,166,163,180,36
                db 5,54,208,186,147,6,215,205,41,87,222,84,191,103,217,35
                db 46,122,102,179,184,74,97,196,2,27,104,93,148,43,111,42
                db 55,190,11,180,161,142,12,195,27,223,5,90,141,239,2,45
                db 0,0,0,0,0,16,22,0,4,16,22,0,8,16,22,0
                db 12,16,22,0,16,16,22,0,20,16,22,0,76,163,82,0
                db 68,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0
                db 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

  @decode_end:
        retn

DecodePassword endp