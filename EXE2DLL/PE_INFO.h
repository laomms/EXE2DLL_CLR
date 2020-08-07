#pragma once
#include <vector>
#include <string>

int GetPeInfo(const char* file_name, std::vector<std::string>& PElist, std::vector<std::string>& DataDirectory, std::vector<std::string>& Sectionlist);