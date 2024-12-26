/*
	This is a simple script that parses certain sections
	of PE files. Coded while learning maldev.
*/

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cout << "USAGE: peparse <FILE_NAME>" << std::endl;
		return EXIT_FAILURE;
	}

	const char* filePath = argv[1];

	HANDLE hFile = CreateFileA(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open file." << std::endl;
		return EXIT_FAILURE;
	}

	HANDLE hMapping = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL
	);

	if (!hMapping) {
		std::cerr << "Failed to create file mapping." << std::endl;
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	LPVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMappedFile) {
		std::cerr << "Failed to map view of file." << std::endl;
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pMappedFile;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		
		return EXIT_FAILURE;
	}
	std::cout << "\n/////////////////// DOS Header ///////////////////" << std::endl;
	std::cout << "Valid DOS signature found." << std::endl;

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pMappedFile + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT signature." << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "\n/////////////////// NT Headers ///////////////////" << std::endl;
	std::cout << "Valid NT signature found." << std::endl;

	IMAGE_FILE_HEADER imageFileHeaders = pImageNtHeaders->FileHeader;
	std::cout << "\nNumber of Sections: " << imageFileHeaders.NumberOfSections << std::endl;

	IMAGE_OPTIONAL_HEADER imageOptionalHeader = pImageNtHeaders->OptionalHeader;
	if (imageOptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		std::cerr << "Invalid Optional Header Magic." << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "\nValid Optional Header Magic found." << std::endl;

	IMAGE_DATA_DIRECTORY dataDir = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	std::cout << "\n/////////////////// Export Table ///////////////////" << std::endl;
	std::cout << std::setw(30) << std::left << "Export Table Virtual Address:" << dataDir.VirtualAddress << std::endl;
	std::cout << std::setw(30) << std::left << "Export Table Size:" << dataDir.Size << std::endl;

	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pMappedFile + dataDir.VirtualAddress);
	std::cout << std::setw(30) << std::left << "Export Directory RVA:" << pImageExportDir << std::endl;

	IMAGE_IMPORT_DESCRIPTOR* pImageImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((PBYTE)pMappedFile 
		+ imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	std::cout << "\n/////////////////// Import Table ///////////////////" << std::endl;
	std::cout << std::setw(30) << std::left << "Import Table Virtual Address:" 
		<< imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;

	std::cout << "\n/////////////////// Section Headers ///////////////////" << std::endl;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (size_t idx = 0; idx < pImageNtHeaders->FileHeader.NumberOfSections; idx++) {
		std::cout << std::setw(20) << std::left << "Section Name:" << std::string((char*)pImageSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME) << std::endl;
		std::cout << std::setw(20) << std::left << "Virtual Address:" << pImageSectionHeader->VirtualAddress << std::endl;
		std::cout << std::setw(20) << std::left << "Size of Raw Data:" << pImageSectionHeader->SizeOfRawData << std::endl;
		std::cout << std::setw(20) << std::left << "Pointer to Raw Data:" << pImageSectionHeader->PointerToRawData << std::endl;
		std::cout << std::setw(20) << std::left << "Pointer to Relocations: " << pImageSectionHeader->PointerToRelocations << std::endl;
		std::cout << std::setw(20) << std::left << "Permissions: ";
		std::cout << ((pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) ? "READ " : "");
		std::cout << ((pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) ? "| WRITE " : "");
		std::cout << ((pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? "| EXECUTE" : "") << std::endl;
		std::cout << std::string(40, '/') << std::endl;
		pImageSectionHeader++;
	}

	UnmapViewOfFile(pMappedFile);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return EXIT_SUCCESS;
}