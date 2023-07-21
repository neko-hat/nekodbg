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
#include "linenoise.h"

char **symbols;
bool can_print_symbols = false;
uint8_t m_saved_data[10] = {0, };
uint64_t bp_list[10] = {0, };
uint16_t bp_cnt = 0;
bool m_enabled;

bool is_prefix(const unsigned char* buffer, const unsigned char* prefix) {
    // 검사할 바이트열의 크기를 계산
    size_t buffer_size = strlen((const char*)buffer);
    // 접두사의 크기를 계산
    size_t prefix_size = strlen((const char*)prefix);

    // 검사할 바이트열의 크기가 접두사보다 작으면 일치할 수 없음
    if (buffer_size < prefix_size) {
        return false;
    }

    // 주어진 크기만큼의 바이트열을 비교하여 접두사와 일치하는지 확인
    if (memcmp(buffer, prefix, prefix_size) == 0) {
        return true;
    }

    return false;
}

void step_over_bp(pid_t pid)
{
    if(bp_cnt)
    {
        int wait_status = 0;
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        uint64_t possible_breakpoint_location = regs.rip -1;
        regs.rip = possible_breakpoint_location;
        disable_break_point(pid, bp_list[0]);
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, &wait_status, 0);
        fprint_wait_status(stderr, wait_status);
        set_break_point(pid, bp_list[0]);
        
    }
}

int set_break_point(pid_t pid, uint64_t addr)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    m_saved_data[0  ] = (uint8_t)(data & 0xff);
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3); 
    if(ptrace(PTRACE_POKEDATA, pid, addr, data_with_int3))
    {
        puts("break point set error!");
        return -1;
    }
    m_enabled = true;
    printf("break point at %#llx\n", addr);
    return 0;
}

int disable_break_point(pid_t pid, uint64_t addr)
{
    uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    uint64_t restored_data = ((data & ~0xff) | m_saved_data[0]);
    ptrace(PTRACE_POKEDATA, pid, addr, restored_data);
    m_enabled = false;
}

void usage(void)
{
    printf("[+]Usage: nekodbg <Target Binart>\n");
    exit(-1);
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

void print_symbols() {
    if (symbols) {
        printf("Symbols:\n");
        for (size_t i = 0; symbols[i] != NULL; ++i) {
            printf("%s\n", symbols[i]);
        }
    } else {
        printf("No symbols found.\n");
    }
}

void free_symbols() {
    if (symbols) {
        // symbols 배열의 메모리 해제
        for (size_t i = 0; symbols[i] != NULL; ++i) {
            free(symbols[i]);
        }
        free(symbols);
        symbols = NULL;
    }
}

long get_vmmap(pid_t pid)
{
    FILE *fp;
    char filename[30];
    char line[0x201];
    long addr;
    char str[20];
    char buf[0x201];

    unsigned long long start_hex, end_hex;
    
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL)
        exit(1);
    puts("\tstart-mapend\t      perm  offset  device  inode\t\t     file");
    while(fgets(line, 0x200, fp) != NULL) {
        sscanf(line, "%llx-%llx", &start_hex, &end_hex);
        printf("%#llx-", start_hex, end_hex);
        char *dash_pos = strchr(line, '-');
        if (dash_pos != NULL) {
            printf("0x%s\n", dash_pos + 1);
        }
    
    }
    fclose(fp); 
    return addr;
}

void view_stack(unsigned long long rsp, pid_t pid)
{
    unsigned long long int data;
    unsigned long long data2;

    for(int i=0; i<10; i++)
    {
        data = ptrace(PTRACE_PEEKDATA, pid, rsp+i*8, 0);
        memcpy(&data2, &data, 4);
        printf("%#llx: ", rsp+i*8);
        printf("%#llx\n", data2);
    }
}

void view_register(struct user_regs_struct *regs, pid_t pid, unsigned int op_size)
{   
    FILE *fp;
    bool flag = true;
    
    char buf[512] = {0, };
    char inst[512] = {0, };
    char opcode[16] = {0, };
    unsigned long instr = ptrace(PTRACE_PEEKDATA,pid,regs->rip,0);
    if(op_size > 0 && op_size <= 15)
    {
        if (opcode == NULL)
        {
            flag = false;
        }
        sprintf(opcode, "%x", instr);
        sprintf(buf, "%s %lx", "/usr/bin/rasm2 -a x86 -b 64 -d", instr);

        fp = popen(buf, "r");
        if (fp == NULL)
            flag = false;
    }
    else
        flag = false;
         
    if (flag)
    {
        fgets(inst, sizeof(inst), fp);
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
        printf("RIP 0x%llx (opcode=%llx -> %s)\n",regs->rip, instr, inst);
        pclose(fp);
    }
    else
    {
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
        printf("RIP 0x%llx (opcode -> %s)\n",regs->rip, "Can't read opcode!");
    }
    
    return;
}

int get_symbols(char *path)
{
    Elf         *elf;
    Elf_Scn     *scn = NULL;
    GElf_Shdr   shdr;
    Elf_Data    *data;
    int         fd, ii, count;

    elf_version(EV_CURRENT);

    fd = open(path, O_RDONLY);
    elf = elf_begin(fd, ELF_C_READ, NULL);

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB) {
            /* found a symbol table, go print it. */
            break;
        }
    }

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize;
    symbols = (char **)malloc((count + 1) * sizeof(char *));
    if (!symbols) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }
    for (size_t i = 0; i < count; ++i) {
        symbols[i] = NULL;
    }
    /* print the symbol names */
    for (ii = 0; ii < count; ++ii) {
        GElf_Sym sym;
        gelf_getsym(data, ii, &sym);
        char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
        symbols[ii] = (char *)malloc(strlen(name)+ 1);
        strncpy(symbols[ii], name, strlen(name));
    }
    elf_end(elf);
    close(fd);
    can_print_symbols = true;
    return 0;
}

void debugger (pid_t pid){
    int wait_status;
    uint8_t op_size = 0;
    unsigned int inst_count=0;
    struct user_regs_struct old_regs;
    struct user_regs_struct regs;
    int options = 0;
    waitpid(pid, &wait_status, options);
    char *before_cmd = NULL;
    char* line = NULL;
    fprint_wait_status(stderr,wait_status);
    while(true){
        
        line = linenoise("neko's debugger > ");

        if (line != NULL)
            before_cmd = line;
        if (line == NULL)
            line = before_cmd;
        
        if(is_prefix(line, "quit"))
        {
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            return 0;
        }
        else if (is_prefix(line, "info regs"))
        {
            view_register(&regs, pid, op_size);
        }
        else if (is_prefix(line, "stack"))
        {
            view_stack(regs.rsp, pid);
        }
        else if(is_prefix(line, "next"))
        {
            ptrace(PTRACE_GETREGS,pid,0,&regs);
            printf("%#llx\n", old_regs.rip);
            if(ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL)){
                fprintf(stderr, "Error fetching registers from child process: %s\n",
                strerror(errno));
                fprint_wait_status(stderr, wait_status);
                return -1;
            }
            printf("%#llx\n", regs.rip);
            inst_count++;
            op_size= regs.rip-old_regs.rip;
            puts("===========================REGS==========================");
            view_register(&regs, pid, op_size);
            puts("==========================STACK==========================");
            view_stack(regs.rsp, pid);
            puts("=========================================================");
            waitpid(pid, &wait_status, options);
            fprint_wait_status(stderr, wait_status);
            old_regs = regs;
        }
        else if(is_prefix(line, "info func"))
        {
            if (can_print_symbols)
                print_symbols();
            else
                puts("there is no symbols...\n");
        }
        else if(is_prefix(line, "continue"))
        {
            step_over_bp(pid);
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            waitpid(pid, &wait_status, options);
            fprint_wait_status(stderr, wait_status);
        }
        else if(is_prefix(line, "vmmap"))
        {
            get_vmmap(pid);
        }
        else if(is_prefix(line, "break"))
        {
            uint64_t addr = 0;
            if(sscanf(line, "break 0x%llx", &addr))
            {
                if(bp_cnt > 9)
                    puts("max bp cnt is 10!!");
                else
                {
                    set_break_point(pid, addr);
                    bp_list[bp_cnt] = addr;
                }
            }
            else
                puts("input break point addr");
        }

    }
    
    printf("[+] total instruction : %u\n",inst_count);
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
        get_symbols(argv[1]);
        if (!can_print_symbols)
            puts("there is no symbols...\n");
        debugger(pid);
        free_symbols();
        return 0;
    }
}