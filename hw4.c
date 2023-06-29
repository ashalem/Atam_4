#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 

#define SHT_SYMTAB (0x2)
#define SHT_STRTAB (0x3)
#define SHT_RELA (0x4)
#define SHT_DYNSYM (0xb)

#define SYM_GLOBAL (0x01)
#define SYM_LOCAL (0x00)

bool checkNameInFile(char *name, FILE *file, long offset) {
    size_t nameLen = strlen(name) + 1;
    fseek(file, offset, SEEK_SET);
    char *symName = (char*)malloc(nameLen);
    fread(symName, nameLen, 1, file);

    printf("name in offset %lu is: %s\n", offset, symName);

    bool isSimilar = (0 == strncmp(name, symName, nameLen));
    free(symName);

    return isSimilar;
}

bool checkDynSymName(char *symbol_name, FILE *elfFile, int idx, 
                    Elf64_Off dynsymTabOffset, 
                    Elf64_Xword dynsymTabSize,
                    Elf64_Xword dynsymTabEntSize,
                    Elf64_Sym *dynsymTab, 
                    Elf64_Off strTabOffset) {
    printf("will check Idx %d in dyn sym for name %s\n", idx, symbol_name);
    
    // Calcualte Sym entry location
    Elf64_Sym *dynSymEntryP =  (Elf64_Sym*)(((char *)dynsymTab) + (dynsymTabEntSize*idx));   

    // Go Check name in Dynsym
    return checkNameInFile(symbol_name, elfFile, strTabOffset + dynSymEntryP->st_name);         
}


unsigned long find_dynSymbol(char *symbol_name, FILE *elfFile, Elf64_Shdr *sectionHeaderTable, Elf64_Half sectionHeaderLen, Elf64_Half sectionHeadeEntrySize, Elf64_Ehdr *elfHeader, Elf64_Off strTabOffset) {
    // Find dynamic symbol header table
    Elf64_Shdr *curr = sectionHeaderTable;
    int i = 0;
    for (i = 0; i < sectionHeaderLen; i++) {
        if (curr->sh_type == SHT_DYNSYM && checkNameInFile(".dynsym", elfFile, sectionHeaderTable[elfHeader->e_shstrndx].sh_offset + curr->sh_name)) {
            break;
        }
        curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
    }

    if (i == sectionHeaderLen) {
        return 0;
    }

    // Found section table entry of the symbol table
    Elf64_Off dynsymTabOffset = curr->sh_offset;
    Elf64_Xword dynsymTabSize = curr->sh_size;
    Elf64_Xword dynsymTabEntSize = curr->sh_entsize;
    Elf64_Sym *dynsymTab = (Elf64_Sym *)malloc(dynsymTabSize);
    fseek(elfFile, dynsymTabOffset, SEEK_SET);
    fread(dynsymTab, dynsymTabSize, 1, elfFile);
    
    
    // Get The relocation table
    curr = sectionHeaderTable;
    i = 0;
    for (i = 0; i < sectionHeaderLen; i++) {
        if (curr->sh_type != SHT_RELA) {// && checkNameInFile(".rela.dyn", elfFile, sectionHeaderTable[elfHeader.e_shstrndx].sh_offset + curr->sh_name)) {
            curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
            continue;
        }
        
        // Found a relocation table
        // Found section table entry of the symbol table
        Elf64_Off relaTabOffset = curr->sh_offset;
        Elf64_Xword relaTabSize = curr->sh_size;
        Elf64_Xword relaTabEntSize = curr->sh_entsize;
        Elf64_Rela *relaTab = (Elf64_Rela *)malloc(relaTabSize);
        fseek(elfFile, relaTabOffset, SEEK_SET);
        fread(relaTab, relaTabSize, 1, elfFile);

        // Go over all rela entries
        Elf64_Rela *currEntr = relaTab;
        int relaTabLen = relaTabSize / relaTabEntSize;
        int k = 0;
        for (k = 0; k < relaTabLen ; k++) {
            // Check if entry is for the wanted symbol
            int dynSymIdx = ELF64_R_SYM(currEntr->r_info);
            if (checkDynSymName(symbol_name, elfFile, dynSymIdx, dynsymTabOffset, dynsymTabSize, dynsymTabEntSize, dynsymTab, strTabOffset)) {
                // Found relevant dynSym entry! <confetti>
                // return the offset of relocation
                return currEntr->r_offset;
            }
            
            
            // Advance rela entries iterator
            currEntr = (Elf64_Rela *)(((char*)currEntr) + relaTabEntSize);
        }

        // Advance section header iterator
        curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
    }

    //Error
    return 0;
}


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	// Open file
    FILE *elfFile = fopen(exe_file_name, "r");
    


    // Parse Elf Header
    Elf64_Ehdr elfHeader = {0};
    fread(&elfHeader, sizeof(elfHeader), 1 , elfFile);

    if (elfHeader.e_type != ET_EXEC) {
        //printf("NOT EXE\n");
        *error_val = -3;
        fclose(elfFile);
        return -3;
    }
    
    
    // Find Section header table
    Elf64_Off sectionHeaderOffset = elfHeader.e_shoff;
    //printf("section header offset: %lx\n", sectionHeaderOffset);
    Elf64_Half sectionHeaderLen = elfHeader.e_shnum;
    Elf64_Half sectionHeadeEntrySize = elfHeader.e_shentsize;
    Elf64_Shdr *sectionHeaderTable = (Elf64_Shdr *)calloc(sectionHeaderLen, sectionHeadeEntrySize);
    fseek(elfFile, sectionHeaderOffset, SEEK_SET);
    fread(sectionHeaderTable, sectionHeadeEntrySize, sectionHeaderLen, elfFile);

    // Find symbol header table
    Elf64_Shdr *curr = sectionHeaderTable;
    int i = 0;
    for (i = 0; i < sectionHeaderLen; i++) {
        if (curr->sh_type == SHT_SYMTAB && checkNameInFile(".symtab", elfFile, sectionHeaderTable[elfHeader.e_shstrndx].sh_offset + curr->sh_name)) {
            break;
        }
        curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
    }

    if (i == sectionHeaderLen) {
        free(sectionHeaderTable);
        fclose(elfFile);
        return -1;
    }

    // Found section table entry of the symbol table
    Elf64_Off symTabOffset = curr->sh_offset;
    Elf64_Xword symTabSize = curr->sh_size;
    Elf64_Xword symTabEntSize = curr->sh_entsize;
    Elf64_Sym *symTab = (Elf64_Sym *)malloc(symTabSize);
    fseek(elfFile, symTabOffset, SEEK_SET);
    fread(symTab, symTabSize, 1, elfFile);


    // Get string Table
    curr = sectionHeaderTable;
    int j = 0;
    for (j = 0; j < sectionHeaderLen; j++) {
        if (curr->sh_type == SHT_STRTAB && checkNameInFile(".strtab", elfFile, sectionHeaderTable[elfHeader.e_shstrndx].sh_offset + curr->sh_name)) {

            //printf("FOUND str tab: %lx\n", curr->sh_offset);
            break;
        }
        curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
    }

    
    if (j == sectionHeaderLen) {
        //printf("DIDN'T FIND STR TABLE\n");
        free(sectionHeaderTable);
        free(symTab);
        fclose(elfFile);
        return -1;
    }

    Elf64_Off strTabOffset = curr->sh_offset;



    // Get dyn string Table
    curr = sectionHeaderTable;
    j = 0;
    for (j = 0; j < sectionHeaderLen; j++) {
        if (curr->sh_type == SHT_STRTAB && checkNameInFile(".dynstr", elfFile, sectionHeaderTable[elfHeader.e_shstrndx].sh_offset + curr->sh_name)) {

            //printf("FOUND str tab: %lx\n", curr->sh_offset);
            break;
        }
        curr = (Elf64_Shdr *)((char *)curr + sectionHeadeEntrySize);
    }

    
    if (j == sectionHeaderLen) {
        //printf("DIDN'T FIND STR TABLE\n");
        free(sectionHeaderTable);
        free(symTab);
        fclose(elfFile);
        return -1;
    }

    Elf64_Off dynstrTabOffset = curr->sh_offset;





    
    // Look for the symbol in the table
    Elf64_Sym *wantedSymbolEnt = symTab;
    int symTabLen = symTabSize / symTabEntSize;
    int k =0;
    bool foundLocal = false;
    for (k = 0; k < symTabLen ; k++) {
        if (checkNameInFile(symbol_name, elfFile, strTabOffset + wantedSymbolEnt->st_name)) {
            // Found symbol <confetti>, check if dymanic
            if (ELF64_ST_BIND(wantedSymbolEnt->st_info) == SYM_GLOBAL) {
                // Check if in this file or not
                if (wantedSymbolEnt->st_shndx == 0) {
                    // Get dyn offset
                    printf("will check dyn sym\n");
                    unsigned long dynOffset = find_dynSymbol(symbol_name, elfFile, sectionHeaderTable, sectionHeaderLen, sectionHeadeEntrySize, &elfHeader, dynstrTabOffset);
                    free(symTab);
                    free(sectionHeaderTable);
                    fclose(elfFile);
                    *error_val = 2; // this will say we are in a dynamic symbol
                    return dynOffset;
                } else {
                    // FOUND
                    *error_val = 1;
                    free(symTab);
                    free(sectionHeaderTable);
                    fclose(elfFile);
                    return wantedSymbolEnt->st_value;
                }
            } else {
                foundLocal = true;
            }
        }

        wantedSymbolEnt = (Elf64_Sym *)(((char*)wantedSymbolEnt) + symTabEntSize);
    }

    if (k == symTabLen) {
        if (foundLocal) {
            *error_val = -2;
            free(symTab);
            free(sectionHeaderTable);
            fclose(elfFile);
            return -2;
        } else {
            //printf("Didn't find sym in sym tab entry"); 
            *error_val = -1;
            free(symTab);
            free(sectionHeaderTable);
            fclose(elfFile);
            return -1;
        }
    }
 

    // Check if symbol is global or dynamic

    // Close file
    fclose(elfFile);
    free(symTab);
    free(sectionHeaderTable);
	return 0;
}

#define SYMBOL_NAME_ARG (1)
#define EXE_NAME_ARG (2)

#define RETURN_ON_ERROR(x) if (x < 0) {return;}


// Set breakpoint on function retAddr
unsigned long setBreakpoint(int sonPid, unsigned long addr) {
        unsigned long originalInstruction = ptrace(PTRACE_PEEKTEXT, sonPid, addr, NULL);
        unsigned long  trapInstruction = (originalInstruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, sonPid, addr, trapInstruction);
        return originalInstruction;
}

int contChild(int sonPid, int *wait_status) {
    ptrace(PTRACE_CONT, sonPid, NULL, NULL);
    waitpid(sonPid, wait_status, 0);
    if (WIFEXITED(*wait_status)) {
        return -1;
    }
}

int singleStepChild(int sonPid, int *wait_status) {
    ptrace(PTRACE_SINGLESTEP, sonPid, NULL, NULL);
    waitpid(sonPid, wait_status, 0);
    if (WIFEXITED(*wait_status)) {
        return -1;
    }
}

void removeBreakpoint(int sonPid, unsigned long addr, unsigned long originalInstruction, struct user_regs_struct *regs) {
    ptrace(PTRACE_POKETEXT, sonPid, addr, originalInstruction);
    regs->rip -= 1;
    ptrace(PTRACE_SETREGS, sonPid, NULL, regs);
}

void debuggerProc(int sonPid, bool isDynamic, unsigned long funcAddr) {
    int wait_status;
    int iCounter = 1;
    unsigned long savedRsp = 0;
    unsigned long addrGOT = funcAddr;
    bool shouldUpdateAddr = isDynamic;

    // Wait for first instruction
    waitpid(sonPid, &wait_status, 0);


    unsigned long originalInstruction = 0;
    if (!isDynamic) {
        // Stage 1 - we are not in Function context - set breakpoint on function first line
        originalInstruction = setBreakpoint(sonPid, funcAddr);
        RETURN_ON_ERROR(contChild(sonPid, &wait_status));
    } else {
        // Stage 1 - Find real function address
        // Set Breakpoint on plt line
        funcAddr = *((unsigned long*)addrGOT);
        originalInstruction = setBreakpoint(sonPid, funcAddr);
        RETURN_ON_ERROR(contChild(sonPid, &wait_status));
    }

    while (true) {
        // Check if we are in function adress, by comparing correct adress to funcAddr
        // Get rip register
        struct user_regs_struct regs;
        unsigned long retAddr;
        ptrace(PTRACE_GETREGS, sonPid, NULL, &regs);
        unsigned long currentAddress = regs.rip -1;

        if (currentAddress == funcAddr) {
            // Stage 2 - now we are in function first line, it was just called
            savedRsp = regs.rsp;
            ptrace(PTRACE_PEEKTEXT, sonPid, savedRsp - 8, &retAddr);
            originalInstruction = setBreakpoint(sonPid, retAddr);
            printf("PRF:: run #%d first parameter is %d\n", iCounter, regs.rdi);
            
        } else {
            // Stage 3 - We are now at the return address - check if in function context or not
            // We do this by comparing saved rsp to current rsp
            if (regs.rsp == savedRsp - 8) {
                // We are in function context,advance one step, return BP at return address, and continue
                removeBreakpoint(sonPid, retAddr, originalInstruction, &regs);
                RETURN_ON_ERROR(singleStepChild(sonPid, &wait_status));
                originalInstruction = setBreakpoint(sonPid, retAddr);
            } else {
                // We are not in function context:
                if (shouldUpdateAddr) {
                    // Update funcAddr to the real one from GOT
                    funcAddr = *((unsigned long*)addrGOT);
                    shouldUpdateAddr = false;
                }
                removeBreakpoint(sonPid, retAddr, originalInstruction, &regs);
                originalInstruction = setBreakpoint(sonPid, funcAddr);
                printf("PRF:: run #%d returned with %d\n", iCounter, regs.rax);
                iCounter++;
            }
        }
        RETURN_ON_ERROR((sonPid, &wait_status));
    }
}

void sonProc(char *const argv[]) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        perror("failed ptrace traceme");
        exit(0);
    }
    execl(argv[EXE_NAME_ARG], *argv[EXE_NAME_ARG], NULL);
    perror("failed execl");
    
}


int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[SYMBOL_NAME_ARG], argv[EXE_NAME_ARG], &err);

	if (err < 0) {
        // Error :(
        if (err == -2)
		    printf("PRF:: <%s> is not a global symbol!\n", argv[SYMBOL_NAME_ARG]);
	    else if (err == -1)
		    printf("PRF:: <%s> not found! :(\n", argv[SYMBOL_NAME_ARG]);
	    else if (err == -3)
		    printf("PRF:: <%s> not an executable!\n\n", argv[EXE_NAME_ARG]);
	    return 0;
    }

    // Good run

    // Fork
    int pid = fork();
    if (pid > 0) {
        // Father process - Debugger
        debuggerProc(pid, (err == 2), addr);
    } else {
        // Son procces - the code
        sonProc(argv);
    }

    return 0;
}