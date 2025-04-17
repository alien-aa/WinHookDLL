.code 
extern log_function:proc   ; log function calls
extern orig_func_bytes:QWORD  ; call original func

Public hook_body          
hook_body proc
    push rbx                
    mov rbx, rsp           
    call orig_func_bytes    
    mov r13, rax           
    mov rsp, rbx            
    pop rbx                 
    call log_function       
    mov rax, r13          
    ret
hook_body endp
end
