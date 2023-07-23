#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>  
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <libelf.h>
#include <errno.h>
#include <gelf.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

uint64_t bp = 0;
bool m_enabled;
uint8_t m_saved_data = 0;

uint64_t view_regs(struct user_regs_struct *regs, pid_t pid)
{
    puts("===========================REGS==========================");
    ptrace(PTRACE_GETREGS,pid,0,regs);
    printf("RAX 0x%llx\n",regs->rax);
    printf("RBX 0x%llx\n",regs->rbx);
    printf("RCX 0x%llx\n",regs->rcx);
    printf("RDX 0x%llx\n",regs->rdx);
    printf("RDI 0x%llx\n",regs->rdi);
    printf("RAX 0x%llx\n",regs->rax);
    printf("RSI 0x%llx\n",regs->rsi);
    printf("R8  0x%llx\n",regs->r8);
    printf("R9  0x%llx\n",regs->r9);
    printf("R10 0x%llx\n",regs->r10);
    printf("R11 0x%llx\n",regs->r11);
    printf("R12 0x%llx\n",regs->r12);
    printf("R13 0x%llx\n",regs->r13);
    printf("R14 0x%llx\n",regs->r14);
    printf("R15 0x%llx\n",regs->r15);
    printf("RBP 0x%llx\n",regs->rbp);
    printf("RSP 0x%llx\n",regs->rsp);
    printf("RIP 0x%llx\n",regs->rip);
    puts("=========================================================");
}

void fprint_wait_status(FILE *stream, int status)
{
    if( WIFSTOPPED(status) ) {
        fprintf(stream, "Child stopped: %d\n", WSTOPSIG(status));
    }
    if( WIFEXITED(status) ) {
        fprintf(stream, "Child exited: %d\n", WEXITSTATUS(status));
    }
    if( WIFSIGNALED(status) ) {
        fprintf(stream, "Child signaled: %d\n", WTERMSIG(status));
    }
    if( WCOREDUMP(status) ) {
        fprintf(stream, "Core dumped.\n");
    }
}

int set_break_point(pid_t pid, uint64_t addr)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    m_saved_data = (uint8_t)(data & 0xff);
    uint64_t int3 = 0xcc;
    long data_with_int3 = ((data & ~0xff) | int3);
    if(ptrace(PTRACE_POKEDATA, pid, addr, data_with_int3))
    {
        puts("break point set error!");
        return -1;
    }
    m_enabled = true;
    bp = addr;
    if(!m_enabled)
        printf("break point at %#llx\n", addr);
    return 0;
}

int disable_break_point(pid_t pid, uint64_t addr)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    long restored_data = ((data & ~0xff) | m_saved_data);
    if(ptrace(PTRACE_POKEDATA, pid, addr, restored_data))
        puts("failed disable bp");
    m_enabled = false;
}

void step_over_bp(pid_t pid)
{   
    if(m_enabled)
    {
        int wait_status = 0;
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        uint64_t possible_breakpoint_location = regs.rip -1;
        regs.rip = possible_breakpoint_location;
        disable_break_point(pid, bp);
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, &wait_status, 0);
        set_break_point(pid, bp);
    }
}

void continue_exec(pid_t pid)
{
    int wait_status = 0;
    step_over_bp(pid);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &wait_status, 0);
}

void view_stack(unsigned long long rsp, pid_t pid)
{
    unsigned long long int data;
    unsigned long long data2;
    puts("==========================STACK==========================");
    for(int i=0; i<10; i++)
    {
        data = ptrace(PTRACE_PEEKDATA, pid, rsp+i*8, 0);
        memcpy(&data2, &data, 8);
        printf("%#llx: ", rsp+i*8);
        printf("%#llx\n", data2);
    }
    puts("=========================================================");
}

void usage(void)
{
    printf("[+]Usage: ./neko_solver silly_chall1\n");
    exit(-1);
}

void debugger (pid_t pid){
    int wait_status;
    unsigned int inst_count=0;
    struct user_regs_struct regs;

    waitpid(pid, &wait_status, 0);

    ptrace(PTRACE_GETREGS,pid,0,&regs);
    long instr = ptrace(PTRACE_PEEKTEXT,pid,regs.rip,0);
    if(ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL)){
            ;
    }
    uint64_t first_bp = 0x0000000000401273;
    uint64_t seccond_bp = 0x0000000000401290;
    view_regs(&regs, pid);
    set_break_point(pid, first_bp);
    continue_exec(pid);
    view_regs(&regs, pid);
    
    uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, (regs.rbp-0x74), NULL);
    ptrace(PTRACE_POKETEXT, pid, (regs.rbp-0x74), data+1);
    printf("[+]CRITICAL: Patch data %#x -> %#x in %#llx\n", (int)data, (int)(data+1), (regs.rbp-0x74));

    disable_break_point(pid, first_bp);
    regs.rip = first_bp;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs))
        puts("can't set");

    set_break_point(pid, seccond_bp);
    continue_exec(pid);
    view_regs(&regs, pid);
    uint64_t old_rax = regs.rax;
    regs.rax = 1;
    disable_break_point(pid, seccond_bp);
    regs.rip = seccond_bp;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs))
       puts("can't set");
    
    printf("[+]CRITICAL: Patch RAX %#llx -> %#llx\n", old_rax, regs.rax);
    uint64_t last_bp = 0x00000000004012a5;
    set_break_point(pid, last_bp);
    continue_exec(pid);
    view_regs(&regs, pid);
    uint64_t neko[] = {0x4152437b47414c46, 0x5f59425f44454b43, 0x5441485f4f4b454e, 0x00000000007d2121};
    uint64_t start_addr = regs.rbp - 0x70;

    view_stack(regs.rbp - 0x70, pid);

    for(int i = 0; i < 4; i++)
    {
        data = ptrace(PTRACE_PEEKTEXT, pid, start_addr+i*8, NULL);
        if(ptrace(PTRACE_POKETEXT, pid, start_addr+i*8, neko[i]))
            puts("can't apply data");
        else
        {
            printf("[+]CRITICAL: Patch Data %#llx -> %#llx in %#llx (-> )", data, neko[i], start_addr+i*8);
            char *tmp = (char *)neko;
            for(int j = 0 ; j < 8; j++)
            {
                printf("%c", *(tmp+i*8+j));
            }
            putchar('\n');
        }
    }
    printf("[+]CRITICAL: Patched Data -> %s\n", (char *)neko);
    view_stack(regs.rbp - 0x70, pid);   
    disable_break_point(pid, bp);
    regs.rip = bp;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs))
       puts("can't set");
    
    printf("[+]CRITICAL GET MSG: ");
}

int main(int argc, char*argv[]){
    if (argc != 2){
        usage();
        return -1;
    }
    pid_t pid = fork();

    if (pid == -1)
    {
        printf("fork error!");
        exit(-1);
    }

    if (pid ==0){
        ptrace(PTRACE_TRACEME, 0, NULL,NULL);
        execl(argv[1],argv[1],NULL);
    }
    
    else{
        debugger(pid);
    }
}