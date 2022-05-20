[GLOBAL f1:function (.f1.end - f1)]
f1:
%assign i 0
%rep    4096 + 600
        nop
%assign i i+1
%endrep
.f1.end:

align 16384,db 0xcc
[GLOBAL f2:function (.f2.end - f2)]
f2:
%assign i 0
%rep    4096
        nop
%assign i i+1
%endrep
.f2.end:

%assign i 0
%rep    6176
        nop
%assign i i+1
%endrep

[GLOBAL f3:function (.f3.end - f3)]
f3:
%assign i 0
%rep    2000
        nop
%assign i i+1
%endrep
.f3.end:

align 4096
