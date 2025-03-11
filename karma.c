#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdlib.h> // for malloc
#include <string.h> // for strcmp
#include <ctype.h>  // for tolower

char* IPv4Fuscation(int firstoctet, int secondoctet, int thirdoctet, int fourthoctet)
{
    // Allocate memory dynamically to avoid returning a pointer to a local variable
    char* ipv4 = (char*)malloc(16); // Enough to hold an IPv4 address in string format
    if (ipv4 == NULL)
    {
        return NULL; // Handle memory allocation failure
    }
    // Format the IPv4 address
    sprintf_s(ipv4, 16, "%d.%d.%d.%d", firstoctet, secondoctet, thirdoctet, fourthoctet);
    return ipv4;
}

BOOL IPv4Output(unsigned char* ipShellcode, SIZE_T ipShellcodeSize)
{
    // Check if the input is valid
    if (ipShellcode == NULL || ipShellcodeSize == 0 || ipShellcodeSize % 4 != 0)
    {
        printf("Error: Shellcode Code Bytes\n");
        return FALSE;
    }

    printf("char* Ipv4Array[%d] = { \n\t", (int)(ipShellcodeSize / 4));

    int counter = 0;
    char* IPv4 = NULL;

    for (SIZE_T i = 0; i < ipShellcodeSize; i += 4)
    {
        counter++;
        IPv4 = IPv4Fuscation(ipShellcode[i], ipShellcode[i + 1], ipShellcode[i + 2], ipShellcode[i + 3]);
        if (IPv4 == NULL)
        {
            printf("Memory allocation error\n");
            return FALSE;
        }
        if (i == ipShellcodeSize - 4)
        {
            // Printing the last IPv4 address
            printf("\"%s\"", IPv4);
        }
        else
        {
            // Printing the IPv4 address
            printf("\"%s\", ", IPv4);
        }

        // Free the dynamically allocated IPv4 string after use
        free(IPv4);

        if (counter % 8 == 0)
        {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}

char* IPv6Fuscation(int firstpartone, int firstparttwo, int secondpartone, int secondparttwo,
    int thirdpartone, int thirdparttwo, int fourthpartone, int fourthparttwo,
    int fifthpartone, int fifthparttwo, int sixthpartone, int sixthparttwo,
    int seventhpartone, int seventhparttwo, int eighthpartone, int eighthparttwo)
{
    char* IPv6 = (char*)malloc(128 * sizeof(char)); // Dynamically allocate memory for IPv6 string

    if (IPv6 == NULL)
    {
        printf("Memory allocation failed\n");
        return NULL;
    }
    // Combining parts to generate the IPv6 address
    sprintf_s(IPv6, 128, "%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X",
        firstpartone, firstparttwo, secondpartone, secondparttwo,
        thirdpartone, thirdparttwo, fourthpartone, fourthparttwo,
        fifthpartone, fifthparttwo, sixthpartone, sixthparttwo,
        seventhpartone, seventhparttwo, eighthpartone, eighthparttwo);

    return IPv6;
}

BOOL GenerateIPv6(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 16 != 0)
    {
        printf("Error In Shellcode Size\n");
        return FALSE;
    }

    printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));

    int c = 16, counter = 0;
    char* IPv6 = NULL;

    for (int i = 0; i < ShellcodeSize; i += 16)
    {
        IPv6 = IPv6Fuscation(
            pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
            pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
            pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
            pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
        );

        if (IPv6 == NULL)
        {
            return FALSE; // Exit if memory allocation failed
        }

        if (i == ShellcodeSize - 16)
        {
            // Printing the last IPv6 address
            printf("\"%s\"", IPv6);
        }
        else
        {
            // Printing the IPv6 address
            printf("\"%s\", ", IPv6);
        }

        free(IPv6); // Free dynamically allocated memory

        c = 1;
        counter++;

        // Optional: To beautify the output on the console
        if (counter % 3 == 0)
        {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}



char* MACFuscation(int fristpart, int secondpart, int thirdpart, int fourthpart, int fifthpart, int sixthpart)
{
    // Dynamiclly Allocating 64 Bytes
    char* MAC = (char*)malloc(64 * sizeof(char));

    // Combining MAC Address Parts and save it to the MAC Variable
    sprintf_s(MAC, 64, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", fristpart, secondpart, thirdpart, fourthpart, fifthpart, sixthpart);


    return MAC;
}


BOOL GenerateMAC(unsigned char* shellcode, SIZE_T shellcodesize)
{
    //Checker
    if (shellcode == NULL || shellcodesize == NULL || shellcodesize % 6 != 0)
    {
        printf("Error In Your Shellcode!\n");
        return EXIT_FAILURE;
    }

    printf("char* MACAddresses [%d] = { \n\t", (int)(shellcodesize / 6));

    int c = 6, counter = 0;
    char* MAC = NULL;

    for (int i = 0; i < shellcodesize; i += 6)
    {
        MAC = MACFuscation(shellcode[i], shellcode[i + 1], shellcode[i + 2], shellcode[i + 3], shellcode[i + 4], shellcode[i + 5]);

        if (MAC == NULL)
        {
            return FALSE; // Exit if memory allocation failed
        }

        if (i == shellcodesize - 6)
        {
            // Printing the last IPv6 address
            printf("\"%s\"", MAC);
        }
        else
        {
            // Printing the IPv6 address
            printf("\"%s\", ", MAC);
        }

        free(MAC); // Free dynamically allocated memory

        c = 1;
        counter++;

        // Optional: To beautify the output on the console
        if (counter % 3 == 0)
        {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}


char* UUIDFuscation(int firstpartone, int firstparttwo, int secondpartone, int secondparttwo,
    int thirdpartone, int thirdparttwo, int fourthpartone, int fourthparttwo,
    int fifthpartone, int fifthparttwo, int sixthpartone, int sixthparttwo,
    int seventhpartone, int seventhparttwo, int eighthpartone, int eighthparttwo) 
{
    char* UUID = (char*)malloc(128 * sizeof(char));
    if (UUID == NULL) 
    {
        printf("Memory allocation for UUID failed\n");
        return NULL;
    }

    // Generating the UUID parts and combining them
    sprintf_s(UUID, 128,
        "%0.2X%0.2X%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
        (unsigned char)secondparttwo, (unsigned char)secondpartone,
        (unsigned char)firstparttwo, (unsigned char)firstpartone,
        (unsigned char)thirdparttwo, (unsigned char)thirdpartone,
        (unsigned char)fourthparttwo, (unsigned char)fourthpartone,
        (unsigned char)fifthpartone, (unsigned char)fifthparttwo,
        (unsigned char)sixthpartone, (unsigned char)sixthparttwo,
        (unsigned char)seventhpartone, (unsigned char)seventhparttwo,
        (unsigned char)eighthpartone, (unsigned char)eighthparttwo);


    return UUID;
}

BOOL GenerateUUID(char* shellcode, SIZE_T shellcodesize)
{
    if (shellcode == NULL || shellcodesize < 16 || shellcodesize % 16 != 0)
    {
        printf("Error in your shellcode!\n");
        return FALSE;
    }
    printf("char* UuidArray[%d] = { \n\t", (int)(shellcodesize / 16));

    char* UUID = NULL;
    for (int i = 0; i < shellcodesize; i += 16)
    {
        UUID = UUIDFuscation(
            shellcode[i], shellcode[i + 1], shellcode[i + 2], shellcode[i + 3],
            shellcode[i + 4], shellcode[i + 5], shellcode[i + 6], shellcode[i + 7],
            shellcode[i + 8], shellcode[i + 9], shellcode[i + 10], shellcode[i + 11],
            shellcode[i + 12], shellcode[i + 13], shellcode[i + 14], shellcode[i + 15]
        );

        if (UUID != NULL)
        {
            if (i + 16 >= shellcodesize)
            {
                printf("\"%s\"", UUID);
            }
            else
            {
                printf("\"%s\", ", UUID);
            }
            free(UUID);
        }
    }
    printf("\n};\n\n");
    return TRUE;
}

char* toLowerStr(char* str) 
{
    for (int i = 0; str[i]; i++)
    {
        str[i] = tolower(str[i]);
    }
    return str;
}


unsigned char* readShellcodeFromFile(const char* filename, size_t* shellcodeSize)
{
    FILE* file;
    if (fopen_s(&file, filename, "rb") != 0 || file == NULL)
    {
        perror("Error opening file");  // This will print a more detailed error message
        return NULL;
    }

    fseek(file, 0, SEEK_END);  // Move to the end of the file
    long size = ftell(file);   // Get the file size
    fseek(file, 0, SEEK_SET);  // Move back to the beginning of the file

    unsigned char* shellcode = (unsigned char*)malloc(size);
    if (shellcode == NULL)
    {
        perror("Memory allocation failed");
        fclose(file); // Don't forget to close the file on error
        return NULL;
    }

    size_t bytesRead = fread(shellcode, 1, size, file);
    if (bytesRead != size)
    {
        perror("Error reading file");
        free(shellcode);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *shellcodeSize = bytesRead;
    return shellcode;
}

// Main function with improved argument handling and mode case-insensitivity
int main(int argc, char* argv[])
{
    printf("\t\t#############################################\n");
    printf("\t\t#    Welcome To Karma Payload Obfuscator    #\n");
    printf("\t\t#############################################\n\n");

    if (argc < 3)
    {
        printf("Available Modes: \nXOR \t(For XOR Encrypting Payload)\nIPv4 \t(For IPv4 Fuscating The Payload)\nIPv6 \t(For IPv6 Fuscating The Payload)\nMAC \t(For MAC Fuscating The Payload)\nUUID \t(For UUID Fuscating The Payload)\n\n");
        printf("Usage: karma.exe mode shellcode.bin\n");
        return EXIT_FAILURE;
    }

    printf("[*] Choosen Mode: %s\n", argv[1]);
    printf("[*] Shellcode File: %s\n", argv[2]);

    char* mode = toLowerStr(argv[1]);

    size_t shellcodeSize;
    char* filename = argv[2];

    unsigned char* shellcode = readShellcodeFromFile(filename, &shellcodeSize);

    printf("[*] Original Payload Size: %d Bytes\n", shellcodeSize);

    if (shellcode == NULL)
    {
        return EXIT_FAILURE;
    }


    int newsize = 0;

    if (strcmp(mode,"ipv4") == 0)
    {
        if (shellcodeSize % 4 != 0)
        {
            printf("[!] Not Optimal Size For IPv4 Fuscation Extending To New Size...\n");

            // Calculate new size
            newsize = (shellcodeSize / 4 + 1) * 4;
            printf("[*] New Payload Size: %d\n", newsize);

            // Resize shellcode and check for failure
            unsigned char* newShellcode = realloc(shellcode, newsize);
            if (newShellcode == NULL) {
                printf("[!] Memory allocation failed\n");
                free(shellcode); // Free original if realloc fails
                return; // Exit or handle error appropriately
            }
            shellcode = newShellcode; // Update shellcode pointer

            // Fill the extra space with NOP instructions (0x90)
            memset(shellcode + shellcodeSize, 0x90, newsize - shellcodeSize);

            // Calculate number of NOPs added
            int nops = newsize - shellcodeSize;
            printf("[!] Filled The Payload With %d NOP Instructions\n", nops);
            printf("[+] IPv4 Fuscating the shellcode...\n");
            IPv4Output(shellcode, newsize);
        }
        else
        {
            printf("[+] IPv4 Fuscating the shellcode...\n");
            IPv4Output(shellcode, shellcodeSize);
        }
        
    }
    else if (strcmp(mode, "ipv6") == 0)
    {
        if (shellcodeSize % 16 != 0)
        {
            printf("[!] Not Optimal Size For IPv6 Fuscation Extending To New Size...\n");

            // Calculate new size
            newsize = (shellcodeSize / 16 + 1) * 16;
            printf("[*] New Payload Size: %d\n", newsize);

            // Resize shellcode and check for failure
            unsigned char* newShellcode = realloc(shellcode, newsize);
            if (newShellcode == NULL) {
                printf("[!] Memory allocation failed\n");
                free(shellcode); // Free original if realloc fails
                return; // Exit or handle error appropriately
            }
            shellcode = newShellcode; // Update shellcode pointer

            // Fill the extra space with NOP instructions (0x90)
            memset(shellcode + shellcodeSize, 0x90, newsize - shellcodeSize);

            // Calculate number of NOPs added
            int nops = newsize - shellcodeSize;
            printf("[!] Filled The Payload With %d NOP Instructions\n", nops);
            printf("[+] IPv6 Fuscating the shellcode...\n");
            GenerateIPv6(shellcode, newsize);
        }
        else
        {
            printf("[+] IPv6 Fuscating the shellcode...\n");
            GenerateIPv6(shellcode, shellcodeSize);
        }
    }
    else if (strcmp(mode, "mac") == 0)
    {
        if (shellcodeSize % 6 != 0)
        {
            printf("[!] Not Optimal Size For MAC Fuscation Extending To New Size...\n");

            // Calculate new size
            newsize = (shellcodeSize / 6 + 1) * 6;
            printf("[*] New Payload Size: %d\n", newsize);

            // Resize shellcode and check for failure
            unsigned char* newShellcode = realloc(shellcode, newsize);
            if (newShellcode == NULL) {
                printf("[!] Memory allocation failed\n");
                free(shellcode); // Free original if realloc fails
                return; // Exit or handle error appropriately
            }
            shellcode = newShellcode; // Update shellcode pointer

            // Fill the extra space with NOP instructions (0x90)
            memset(shellcode + shellcodeSize, 0x90, newsize - shellcodeSize);

            // Calculate number of NOPs added
            int nops = newsize - shellcodeSize;
            printf("[!] Filled The Payload With %d NOP Instructions\n", nops);
            printf("[+] MAC Fuscating the shellcode...\n");
            GenerateMAC(shellcode, newsize);
        }
        else
        {
            printf("[+] MAC Fuscating the shellcode...\n");
            GenerateMAC(shellcode, shellcodeSize);
        }
    }
    else if (strcmp(mode, "uuid") == 0)
    {
        if (shellcodeSize % 16 != 0)
        {
            printf("[!] Not Optimal Size For UUID Fuscation Extending To New Size...\n");

            // Calculate new size
            newsize = (shellcodeSize / 16 + 1) * 16;
            printf("[*] New Payload Size: %d\n", newsize);

            // Resize shellcode and check for failure
            unsigned char* newShellcode = realloc(shellcode, newsize);
            if (newShellcode == NULL) {
                printf("[!] Memory allocation failed\n");
                free(shellcode); // Free original if realloc fails
                return; // Exit or handle error appropriately
            }
            shellcode = newShellcode; // Update shellcode pointer

            // Fill the extra space with NOP instructions (0x90)
            memset(shellcode + shellcodeSize, 0x90, newsize - shellcodeSize);

            // Calculate number of NOPs added
            int nops = newsize - shellcodeSize;
            printf("[!] Filled The Payload With %d NOP Instructions\n", nops);
            printf("[+] UUID Fuscating the shellcode...\n");
            GenerateUUID((char*)shellcode, newsize);
        }
        else
        {
            printf("[+] UUID Fuscating the shellcode...\n");
            GenerateUUID((char*)shellcode, shellcodeSize);
        }
    }
    else
    {
        printf("[!] Invalid Mode!\n");
        return EXIT_FAILURE;
    }

    free(shellcode);

    printf("Thanks For Using Karma!\n");
    return EXIT_SUCCESS;
}
